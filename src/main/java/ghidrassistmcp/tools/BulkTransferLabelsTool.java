/*
 * MCP tool that bulk-transfers function names and prototypes to a target program.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Bulk-transfers function names and optionally prototypes from match results
 * to a target program. Accepts a JSON array of match entries, each with
 * target_addr, name, and optional prototype.
 */
public class BulkTransferLabelsTool implements McpTool {

    @Override
    public String getName() {
        return "bulk_transfer_labels";
    }

    @Override
    public String getDescription() {
        return "Bulk-apply function names and prototypes to a target program. " +
               "Input: JSON array as 'transfers' parameter, each with 'target_addr' (hex address), " +
               "'name' (new function name), and optional 'prototype' (C signature). " +
               "Reports success/failure per entry. Use after string_anchor_matcher or function_byte_matcher.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @SuppressWarnings("unchecked")
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "transfers", Map.of(
                    "type", "array",
                    "description", "Array of transfers: [{\"target_addr\": \"0x...\", \"name\": \"funcName\", \"prototype\": \"optional C sig\"}]",
                    "items", Map.of(
                        "type", "object",
                        "properties", Map.of(
                            "target_addr", Map.of("type", "string", "description", "Address in target program"),
                            "name", Map.of("type", "string", "description", "Function name to apply"),
                            "prototype", Map.of("type", "string", "description", "Optional: C function prototype/signature")
                        ),
                        "required", List.of("target_addr", "name")
                    )
                ),
                "target_program", Map.of("type", "string", "description", "Name of the target program to apply labels to"),
                "dry_run", Map.of("type", "boolean", "description", "If true, validate without applying changes (default false)", "default", false)
            ),
            List.of("transfers", "target_program"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @SuppressWarnings("unchecked")
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        String targetProgramName = (String) arguments.get("target_program");
        boolean dryRun = false;
        if (arguments.get("dry_run") instanceof Boolean)
            dryRun = (Boolean) arguments.get("dry_run");

        Program targetProgram = findProgram(backend, targetProgramName);
        if (targetProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Target program not found: " + targetProgramName)
                .build();
        }

        Object transfersObj = arguments.get("transfers");
        if (!(transfersObj instanceof List)) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("'transfers' must be a JSON array")
                .build();
        }

        List<Map<String, Object>> transfers = (List<Map<String, Object>>) transfersObj;

        int successCount = 0;
        int failCount = 0;
        int skipCount = 0;
        List<String> errors = new ArrayList<>();

        int txId = -1;
        if (!dryRun) {
            txId = targetProgram.startTransaction("Bulk Transfer Labels");
        }

        try {
            for (int i = 0; i < transfers.size(); i++) {
                Map<String, Object> entry = transfers.get(i);
                String targetAddr = (String) entry.get("target_addr");
                String name = (String) entry.get("name");
                String prototype = entry.get("prototype") instanceof String ?
                    (String) entry.get("prototype") : null;

                if (targetAddr == null || name == null) {
                    errors.add(String.format("#%d: missing target_addr or name", i + 1));
                    failCount++;
                    continue;
                }

                try {
                    Address addr = targetProgram.getAddressFactory().getAddress(targetAddr);
                    if (addr == null) {
                        errors.add(String.format("#%d: invalid address %s", i + 1, targetAddr));
                        failCount++;
                        continue;
                    }

                    Function func = targetProgram.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        // Try to find function containing this address
                        func = targetProgram.getFunctionManager().getFunctionContaining(addr);
                        if (func == null) {
                            errors.add(String.format("#%d: no function at %s (%s)", i + 1, targetAddr, name));
                            failCount++;
                            continue;
                        }
                    }

                    // Skip if already has this name
                    if (func.getName().equals(name)) {
                        skipCount++;
                        continue;
                    }

                    if (!dryRun) {
                        // Apply name
                        func.setName(name, SourceType.IMPORTED);

                        // Apply prototype if provided
                        if (prototype != null && !prototype.isEmpty()) {
                            try {
                                var dtm = targetProgram.getDataTypeManager();
                                var parser = new ghidra.app.util.cparser.C.CParser(dtm);
                                var sig = parser.parse(prototype + ";");
                                if (sig != null) {
                                    var cmd = new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                                        func.getEntryPoint(),
                                        (ghidra.program.model.data.FunctionDefinition) sig,
                                        SourceType.IMPORTED);
                                    cmd.applyTo(targetProgram);
                                }
                            } catch (Exception e) {
                                // Name was applied, prototype failed - partial success
                                errors.add(String.format("#%d: name OK, prototype failed for %s: %s",
                                    i + 1, name, e.getMessage()));
                            }
                        }
                    }

                    successCount++;

                } catch (Exception e) {
                    errors.add(String.format("#%d: %s - %s", i + 1, name, e.getMessage()));
                    failCount++;
                }
            }

            if (!dryRun && txId >= 0) {
                targetProgram.endTransaction(txId, true);
            }

        } catch (Exception e) {
            if (!dryRun && txId >= 0) {
                targetProgram.endTransaction(txId, false);
            }
            return McpSchema.CallToolResult.builder()
                .addTextContent("Transaction failed: " + e.getMessage())
                .build();
        }

        // Format results
        StringBuilder result = new StringBuilder();
        result.append("Bulk Transfer Labels Report\n");
        result.append("==========================\n");
        result.append("Target: ").append(targetProgramName).append("\n");
        if (dryRun) result.append("MODE: DRY RUN (no changes applied)\n");
        result.append("\n");
        result.append("Total entries: ").append(transfers.size()).append("\n");
        result.append("Successful: ").append(successCount).append("\n");
        result.append("Skipped (already named): ").append(skipCount).append("\n");
        result.append("Failed: ").append(failCount).append("\n");

        if (!errors.isEmpty()) {
            result.append("\nErrors:\n");
            for (String err : errors) {
                result.append("  - ").append(err).append("\n");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    private Program findProgram(GhidrAssistMCPBackend backend, String name) {
        for (Program p : backend.getAllOpenPrograms()) {
            if (p.getName().equals(name)) return p;
        }
        return null;
    }
}
