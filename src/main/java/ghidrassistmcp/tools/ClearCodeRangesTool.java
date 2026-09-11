/*
 * ClearCodeRangesTool - Clear functions, instructions, and/or data in address ranges
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that clears functions, instructions, and/or data in specified address ranges.
 * Useful for re-analysis workflows and cleaning up incorrect auto-analysis.
 */
public class ClearCodeRangesTool implements McpTool {
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isDestructive() { return true; }

    @Override
    public String getName() {
        return "clear_code_ranges";
    }

    @Override
    public String getDescription() {
        return "Clear functions, instructions, and/or data in specified address ranges. " +
               "Format ranges as 'start-end' pairs separated by commas (e.g., '0x1000-0x2000,0x3000-0x4000'). " +
               "Use dry_run=true to see what would be cleared without making changes.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "ranges", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "clear_functions", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "clear_instructions", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "clear_data", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "dry_run", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of("ranges"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        // Get parameters
        String rangesStr = (String) arguments.get("ranges");
        Boolean clearFunctions = (Boolean) arguments.get("clear_functions");
        Boolean clearInstructions = (Boolean) arguments.get("clear_instructions");
        Boolean clearData = (Boolean) arguments.get("clear_data");
        Boolean dryRun = (Boolean) arguments.get("dry_run");

        if (rangesStr == null || rangesStr.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("ranges parameter is required")
                .build();
        }

        // Defaults
        if (clearFunctions == null) clearFunctions = true;
        if (clearInstructions == null) clearInstructions = true;
        if (clearData == null) clearData = true;
        if (dryRun == null) dryRun = false;

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

        // Process each range
        List<ClearResult> results = new ArrayList<>();
        FunctionManager funcManager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        // Count what would be cleared (always do this for reporting)
        for (AddressRange range : ranges) {
            ClearResult result = new ClearResult();
            result.start = range.start;
            result.end = range.end;

            // Count functions in range
            if (clearFunctions) {
                FunctionIterator funcIter = funcManager.getFunctions(range.start, true);
                while (funcIter.hasNext()) {
                    Function func = funcIter.next();
                    if (func.getEntryPoint().compareTo(range.end) >= 0) break;
                    result.functionsCount++;
                }
            }

            // Count instructions and data in range
            CodeUnitIterator codeUnits = listing.getCodeUnits(range.start, true);
            while (codeUnits.hasNext()) {
                CodeUnit cu = codeUnits.next();
                if (cu.getAddress().compareTo(range.end) >= 0) break;

                if (cu instanceof Instruction && clearInstructions) {
                    result.instructionsCount++;
                } else if (cu instanceof Data && clearData) {
                    Data data = (Data) cu;
                    if (data.isDefined()) {
                        result.dataCount++;
                    }
                }
            }

            results.add(result);
        }

        // If dry run, just report what would be cleared
        if (dryRun) {
            return buildReport(results, true);
        }

        // Perform the actual clearing within a transaction
        int transactionID = currentProgram.startTransaction("Clear Code Ranges");
        try {
            for (int i = 0; i < ranges.size(); i++) {
                AddressRange range = ranges.get(i);
                ClearResult result = results.get(i);

                // Clear functions first
                if (clearFunctions) {
                    List<Address> funcAddresses = new ArrayList<>();
                    FunctionIterator funcIter = funcManager.getFunctions(range.start, true);
                    while (funcIter.hasNext()) {
                        Function func = funcIter.next();
                        if (func.getEntryPoint().compareTo(range.end) >= 0) break;
                        funcAddresses.add(func.getEntryPoint());
                    }
                    for (Address funcAddr : funcAddresses) {
                        funcManager.removeFunction(funcAddr);
                    }
                    result.functionsCleared = funcAddresses.size();
                }

                // Clear code units (instructions and/or data)
                if (clearInstructions || clearData) {
                    // Use clearCodeUnits which clears both instructions and defined data
                    // The third parameter (clearContext) is set to false to preserve register context
                    listing.clearCodeUnits(range.start, range.end.subtract(1), false);
                    result.instructionsCleared = result.instructionsCount;
                    result.dataCleared = result.dataCount;
                }
            }

            currentProgram.endTransaction(transactionID, true);
            return buildReport(results, false);

        } catch (Exception e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error clearing code ranges: " + e.getMessage())
                .build();
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

            // Split by dash (but handle hex addresses that might start with 0x)
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
        // Find dash that's not part of a hex number
        // Look for pattern like "0x....-0x...." or "....-0x...." or "0x....-..."
        int lastDash = range.lastIndexOf('-');
        if (lastDash <= 0) return -1;

        // Check if this dash is followed by 0x (meaning it's a separator before hex number)
        // or if it's preceded by a hex digit (meaning it's likely the separator)
        String afterDash = range.substring(lastDash + 1).trim();
        if (afterDash.startsWith("0x") || afterDash.startsWith("0X")) {
            return lastDash;
        }

        // Otherwise use the last dash
        return lastDash;
    }

    /**
     * Build the result report.
     */
    private McpSchema.CallToolResult buildReport(List<ClearResult> results, boolean isDryRun) {
        StringBuilder report = new StringBuilder();

        if (isDryRun) {
            report.append("DRY RUN - Clear Code Ranges Analysis:\n\n");
        } else {
            report.append("Clear Code Ranges Result:\n\n");
        }

        int totalFunctions = 0;
        int totalInstructions = 0;
        int totalData = 0;

        for (int i = 0; i < results.size(); i++) {
            ClearResult r = results.get(i);
            report.append("Range ").append(i + 1).append(": ");
            report.append(r.start).append(" - ").append(r.end).append("\n");

            if (isDryRun) {
                report.append("  Functions to clear: ").append(r.functionsCount).append("\n");
                report.append("  Instructions to clear: ").append(r.instructionsCount).append("\n");
                report.append("  Data items to clear: ").append(r.dataCount).append("\n");
                totalFunctions += r.functionsCount;
                totalInstructions += r.instructionsCount;
                totalData += r.dataCount;
            } else {
                report.append("  Functions cleared: ").append(r.functionsCleared).append("\n");
                report.append("  Instructions cleared: ").append(r.instructionsCleared).append("\n");
                report.append("  Data items cleared: ").append(r.dataCleared).append("\n");
                totalFunctions += r.functionsCleared;
                totalInstructions += r.instructionsCleared;
                totalData += r.dataCleared;
            }
            report.append("\n");
        }

        report.append("Totals:\n");
        report.append("  Functions: ").append(totalFunctions).append("\n");
        report.append("  Instructions: ").append(totalInstructions).append("\n");
        report.append("  Data items: ").append(totalData).append("\n\n");

        if (isDryRun) {
            report.append("Status: DRY RUN COMPLETE - No changes made");
        } else {
            report.append("Status: SUCCESS");
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(report.toString())
            .build();
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

    /**
     * Helper class to track clearing results.
     */
    private static class ClearResult {
        Address start;
        Address end;
        int functionsCount = 0;
        int instructionsCount = 0;
        int dataCount = 0;
        int functionsCleared = 0;
        int instructionsCleared = 0;
        int dataCleared = 0;
    }
}
