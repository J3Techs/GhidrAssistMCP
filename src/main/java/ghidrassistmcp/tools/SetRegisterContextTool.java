/*
 * SetRegisterContextTool - Set processor register context values over address ranges
 */
package ghidrassistmcp.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that sets processor register context values over address ranges.
 * Critical for architectures like TriCore where segment registers (A0, A1, A8, A9)
 * affect addressing modes and data pointer resolution.
 */
public class SetRegisterContextTool implements McpTool {

    @Override
    public boolean isReadOnly() { return false; }

    @Override
    public String getName() {
        return "set_register_context";
    }

    @Override
    public String getDescription() {
        return "Set processor register context values over address ranges. " +
               "Essential for TriCore analysis where segment registers (A0, A1, A8, A9) affect addressing. " +
               "Modes: 'overwrite' (replace), 'set_if_unset' (skip if exists), 'merge' (OR with existing).";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "register", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "value", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "ranges", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "mode", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "dry_run", Map.of("type", "boolean", "description", "Preview without writing (default false)", "default", false)
            ),
            List.of("register", "value", "ranges"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("No program currently loaded").build();
        }

        // Get parameters
        String registerName = (String) arguments.get("register");
        String valueStr = (String) arguments.get("value");
        String rangesStr = (String) arguments.get("ranges");
        String mode = (String) arguments.get("mode");
        boolean dryRun = Boolean.TRUE.equals(arguments.get("dry_run"));

        if (registerName == null || valueStr == null || rangesStr == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("register, value, and ranges parameters are required").build();
        }

        // Default mode
        if (mode == null) {
            mode = "overwrite";
        }

        // Validate mode
        if (!mode.equals("overwrite") && !mode.equals("set_if_unset") && !mode.equals("merge")) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Invalid mode: " + mode + ". Must be 'overwrite', 'set_if_unset', or 'merge'").build();
        }

        // Resolve register
        ProgramContext context = currentProgram.getProgramContext();
        Register register = resolveRegister(context, registerName);
        if (register == null) {
            // Build list of available registers
            StringBuilder availableRegs = new StringBuilder();
            availableRegs.append("Register '").append(registerName).append("' not found.\n\n");
            availableRegs.append("Available registers:\n");
            int count = 0;
            for (Register reg : context.getRegisters()) {
                if (!reg.isHidden() && count < 50) {
                    availableRegs.append("  ").append(reg.getName());
                    if (reg.getBitLength() > 0) {
                        availableRegs.append(" (").append(reg.getBitLength()).append(" bits)");
                    }
                    availableRegs.append("\n");
                    count++;
                }
            }
            if (count == 50) {
                availableRegs.append("  ... (more registers available)\n");
            }
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent(availableRegs.toString()).build();
        }

        // Parse value as BigInteger
        BigInteger value;
        try {
            value = parseValue(valueStr);
        } catch (NumberFormatException e) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Invalid value format: " + valueStr + ". Use decimal or hex (0x prefix).").build();
        }

        // Parse ranges
        List<AddressRange> ranges;
        try {
            ranges = parseRanges(currentProgram, rangesStr);
        } catch (IllegalArgumentException e) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Invalid ranges format: " + e.getMessage()).build();
        }

        if (ranges.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("No valid ranges specified").build();
        }

        // Apply register context within a transaction
        List<Map<String, Object>> changes = new ArrayList<>();
        int transactionID = dryRun ? -1 : currentProgram.startTransaction("Set Register Context");
        try {
            int rangesUpdated = 0;
            int rangesSkipped = 0;
            List<String> notes = new ArrayList<>();
            int segmentsInspected = 0;

            for (AddressRange range : ranges) {
                List<ValueSegment> segments = valueSegments(context, register, range, 10000 - segmentsInspected);
                segmentsInspected += segments.size();
                BigInteger beforeStart = segments.isEmpty() ? null : segments.get(0).value;
                BigInteger beforeEnd = segments.isEmpty() ? null : segments.get(segments.size() - 1).value;
                switch (mode) {
                    case "overwrite":
                        if (!dryRun) context.setValue(register, range.start, range.end.subtract(1), value);
                        rangesUpdated++;
                        changes.add(change(range, beforeStart, beforeEnd, value, "overwrite", dryRun));
                        break;
                    case "set_if_unset":
                        for (ValueSegment segment : segments) {
                            if (segment.value == null) {
                                if (!dryRun) context.setValue(register, segment.start, segment.end.subtract(1), value);
                                rangesUpdated++;
                                changes.add(change(segment.start, segment.end, segment.value, value, "set", dryRun));
                            } else {
                                rangesSkipped++;
                            }
                        }
                        break;

                    case "merge":
                        // OR with existing value
                        for (ValueSegment segment : segments) {
                            BigInteger current = segment.value;
                            BigInteger merged = current != null ? current.or(value) : value;
                            if (!dryRun) context.setValue(register, segment.start, segment.end.subtract(1), merged);
                            rangesUpdated++;
                            changes.add(change(segment.start, segment.end, segment.value, merged, "merge", dryRun));
                            if (current != null) {
                                notes.add("Merged at " + segment.start + ": 0x" + current.toString(16) +
                                         " | 0x" + value.toString(16) + " = 0x" + merged.toString(16));
                            }
                        }
                        break;
                }
            }

            if (!dryRun) currentProgram.endTransaction(transactionID, true);

            // Build structured result
            Map<String, Object> result = new java.util.LinkedHashMap<>();
            result.put("register", register.getName()); result.put("value", "0x" + value.toString(16));
            result.put("mode", mode); result.put("dry_run", dryRun);
            result.put("ranges_updated", rangesUpdated); result.put("ranges_skipped", rangesSkipped);
            result.put("changes", changes); result.put("notes", notes);
            result.put("status", "SUCCESS");
            return ProjectToolSupport.result(result);

        } catch (Exception e) {
            if (!dryRun && transactionID >= 0) currentProgram.endTransaction(transactionID, false);
            return ProjectToolSupport.error("Error setting register context: " + e.getMessage());
        }
    }

    /**
     * Resolve register by name (case-insensitive).
     */
    private Register resolveRegister(ProgramContext context, String registerName) {
        // Try exact match first
        Register reg = context.getRegister(registerName);
        if (reg != null) {
            return reg;
        }

        // Try case-insensitive match
        for (Register r : context.getRegisters()) {
            if (r.getName().equalsIgnoreCase(registerName)) {
                return r;
            }
        }

        return null;
    }

    /**
     * Parse value string as BigInteger. Supports hex (0x prefix) and decimal.
     */
    private BigInteger parseValue(String valueStr) throws NumberFormatException {
        valueStr = valueStr.trim();
        if (valueStr.toLowerCase().startsWith("0x")) {
            return new BigInteger(valueStr.substring(2), 16);
        } else {
            return new BigInteger(valueStr);
        }
    }

    /**
     * Parse ranges string into list of AddressRange objects.
     * Format: half-open "0x1000-0x2000,0x3000-0x4000" ranges ([start,end)).
     */
    static List<AddressRange> parseRanges(Program program, String rangesStr) throws IllegalArgumentException {
        List<AddressRange> ranges = new ArrayList<>();

        // Split by comma
        String[] rangeParts = rangesStr.split(",");
        if (rangeParts.length > 1000) throw new IllegalArgumentException("At most 1000 ranges are allowed");
        for (String rangePart : rangeParts) {
            rangePart = rangePart.trim();
            if (rangePart.isEmpty()) continue;

            // Split by dash (handle hex addresses)
            int dashIndex = findRangeSeparator(rangePart);
            if (dashIndex == -1) {
                throw new IllegalArgumentException("Invalid range format: " + rangePart +
                    ". Expected 'start-end' format.");
            }

            String startStr = rangePart.substring(0, dashIndex).trim();
            String endStr = rangePart.substring(dashIndex + 1).trim();

            Address start = program.getAddressFactory().getAddress(startStr);
            Address end = program.getAddressFactory().getAddress(endStr);

            if (start == null) {
                throw new IllegalArgumentException("Invalid start address: " + startStr);
            }
            if (end == null) {
                throw new IllegalArgumentException("Invalid end address: " + endStr);
            }
            if (start.compareTo(end) >= 0) {
                throw new IllegalArgumentException("Start address must be less than end address: " + rangePart);
            }

            ranges.add(new AddressRange(start, end));
        }

        return ranges;
    }

    /**
     * Find the separator dash in a range string, handling hex addresses.
     */
    private static int findRangeSeparator(String range) {
        int lastDash = range.lastIndexOf('-');
        if (lastDash <= 0) return -1;

        String afterDash = range.substring(lastDash + 1).trim();
        if (afterDash.startsWith("0x") || afterDash.startsWith("0X")) {
            return lastDash;
        }

        return lastDash;
    }

    /**
     * Helper class to represent an address range.
     */
    static class AddressRange {
        final Address start;
        final Address end;

        AddressRange(Address start, Address end) {
            this.start = start;
            this.end = end;
        }
    }

    static List<ValueSegment> valueSegments(ProgramContext context, Register register,
                                            AddressRange requested, int maxSegments) {
        List<ValueSegment> result = new ArrayList<>();
        Address cursor = requested.start;
        AddressRangeIterator iterator = context.getRegisterValueAddressRanges(register, requested.start, requested.end.subtract(1));
        while (iterator.hasNext()) {
            if (Thread.currentThread().isInterrupted()) throw new IllegalArgumentException("Register context operation cancelled");
            ghidra.program.model.address.AddressRange defined = iterator.next();
            if (defined.getMinAddress().compareTo(requested.end) >= 0) break;
            Address start = defined.getMinAddress().compareTo(requested.start) < 0 ? requested.start : defined.getMinAddress();
            Address endExclusive = defined.getMaxAddress().compareTo(requested.end.subtract(1)) >= 0
                    ? requested.end : defined.getMaxAddress().add(1);
            if (endExclusive.compareTo(requested.start) <= 0 || start.compareTo(requested.end) >= 0) continue;
            if (cursor.compareTo(start) < 0) { addSegment(result, new ValueSegment(cursor, start, null), maxSegments); }
            if (start.compareTo(cursor) < 0) start = cursor;
            if (start.compareTo(endExclusive) < 0) {
                addSegment(result, new ValueSegment(start, endExclusive, context.getValue(register, start, false)), maxSegments);
                cursor = endExclusive;
            }
        }
        if (cursor.compareTo(requested.end) < 0)
            addSegment(result, new ValueSegment(cursor, requested.end, null), maxSegments);
        return result;
    }

    private static void addSegment(List<ValueSegment> result, ValueSegment segment, int maxSegments) {
        if (result.size() >= maxSegments) throw new IllegalArgumentException("Register segment limit exceeded; use smaller ranges");
        result.add(segment);
    }

    static class ValueSegment {
        final Address start, end; final BigInteger value;
        ValueSegment(Address start, Address end, BigInteger value) { this.start = start; this.end = end; this.value = value; }
    }

    private static String format(BigInteger value) { return value == null ? "unset" : "0x" + value.toString(16); }

    private static Map<String, Object> change(AddressRange range, BigInteger start, BigInteger end,
                                               BigInteger after, String action, boolean dryRun) {
        Map<String, Object> c = new java.util.LinkedHashMap<>();
        c.put("start", range.start.toString()); c.put("end", range.end.toString());
        c.put("before_start", format(start)); c.put("before_end", format(end));
        c.put("after", format(after)); c.put("action", action); c.put("applied", !dryRun);
        return c;
    }

    private static Map<String, Object> change(Address start, Address end, BigInteger before,
                                               BigInteger after, String action, boolean dryRun) {
        Map<String, Object> c = new java.util.LinkedHashMap<>();
        c.put("start", start.toString()); c.put("end", end.toString());
        c.put("before", format(before)); c.put("after", format(after));
        c.put("action", action); c.put("applied", !dryRun); return c;
    }
}
