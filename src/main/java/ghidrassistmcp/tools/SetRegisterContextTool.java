/*
 * SetRegisterContextTool - Set processor register context values over address ranges
 */
package ghidrassistmcp.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
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
                "mode", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("register", "value", "ranges"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        // Get parameters
        String registerName = (String) arguments.get("register");
        String valueStr = (String) arguments.get("value");
        String rangesStr = (String) arguments.get("ranges");
        String mode = (String) arguments.get("mode");

        if (registerName == null || valueStr == null || rangesStr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("register, value, and ranges parameters are required")
                .build();
        }

        // Default mode
        if (mode == null) {
            mode = "overwrite";
        }

        // Validate mode
        if (!mode.equals("overwrite") && !mode.equals("set_if_unset") && !mode.equals("merge")) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid mode: " + mode + ". Must be 'overwrite', 'set_if_unset', or 'merge'")
                .build();
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
                .addTextContent(availableRegs.toString())
                .build();
        }

        // Parse value as BigInteger
        BigInteger value;
        try {
            value = parseValue(valueStr);
        } catch (NumberFormatException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid value format: " + valueStr + ". Use decimal or hex (0x prefix).")
                .build();
        }

        // Parse ranges
        List<AddressRange> ranges;
        try {
            ranges = parseRanges(currentProgram, rangesStr);
        } catch (IllegalArgumentException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid ranges format: " + e.getMessage())
                .build();
        }

        if (ranges.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No valid ranges specified")
                .build();
        }

        // Apply register context within a transaction
        int transactionID = currentProgram.startTransaction("Set Register Context");
        try {
            int rangesUpdated = 0;
            int rangesSkipped = 0;
            List<String> notes = new ArrayList<>();

            for (AddressRange range : ranges) {
                switch (mode) {
                    case "overwrite":
                        context.setValue(register, range.start, range.end.subtract(1), value);
                        rangesUpdated++;
                        break;

                    case "set_if_unset":
                        // Check if register has a value at the start of the range
                        BigInteger existing = context.getValue(register, range.start, false);
                        if (existing == null) {
                            context.setValue(register, range.start, range.end.subtract(1), value);
                            rangesUpdated++;
                        } else {
                            rangesSkipped++;
                            notes.add("Skipped " + range.start + "-" + range.end +
                                     " (existing value: 0x" + existing.toString(16) + ")");
                        }
                        break;

                    case "merge":
                        // OR with existing value
                        BigInteger current = context.getValue(register, range.start, false);
                        BigInteger merged = current != null ? current.or(value) : value;
                        context.setValue(register, range.start, range.end.subtract(1), merged);
                        rangesUpdated++;
                        if (current != null) {
                            notes.add("Merged at " + range.start + ": 0x" + current.toString(16) +
                                     " | 0x" + value.toString(16) + " = 0x" + merged.toString(16));
                        }
                        break;
                }
            }

            currentProgram.endTransaction(transactionID, true);

            // Build result
            StringBuilder result = new StringBuilder();
            result.append("Set Register Context Result:\n\n");
            result.append("Register: ").append(register.getName()).append("\n");
            result.append("Value: 0x").append(value.toString(16)).append("\n");
            result.append("Mode: ").append(mode).append("\n\n");
            result.append("Ranges updated: ").append(rangesUpdated).append("\n");
            if (rangesSkipped > 0) {
                result.append("Ranges skipped: ").append(rangesSkipped).append("\n");
            }

            if (!notes.isEmpty()) {
                result.append("\nNotes:\n");
                for (String note : notes) {
                    result.append("  ").append(note).append("\n");
                }
            }

            result.append("\nStatus: SUCCESS");

            return McpSchema.CallToolResult.builder()
                .addTextContent(result.toString())
                .build();

        } catch (Exception e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error setting register context: " + e.getMessage())
                .build();
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
     * Format: "0x1000-0x2000,0x3000-0x4000" or "0x1000-0x2000"
     */
    private List<AddressRange> parseRanges(Program program, String rangesStr) throws IllegalArgumentException {
        List<AddressRange> ranges = new ArrayList<>();

        // Split by comma
        String[] rangeParts = rangesStr.split(",");
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
    private int findRangeSeparator(String range) {
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
    private static class AddressRange {
        Address start;
        Address end;

        AddressRange(Address start, Address end) {
            this.start = start;
            this.end = end;
        }
    }
}
