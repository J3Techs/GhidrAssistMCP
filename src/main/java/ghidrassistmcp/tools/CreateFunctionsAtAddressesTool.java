/*
 * MCP tool that creates function definitions at specified addresses.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Creates function definitions at specified addresses in a target program.
 * Disassembles bytes at each address first, then defines a function there.
 * Skips addresses that already have a function defined.
 * Useful for fixing missing function definitions before bulk label transfers.
 */
public class CreateFunctionsAtAddressesTool implements McpTool {

    @Override
    public String getName() {
        return "create_functions_at_addresses";
    }

    @Override
    public String getDescription() {
        return "Create function definitions at specified addresses. " +
               "Disassembles bytes at each address first, then defines a function. " +
               "Skips addresses that already have a function defined. " +
               "Applies atomically: any failed address rolls back all changes made by this call.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override public boolean isLongRunning() { return true; }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "target_program", Map.of("type", "string",
                    "description", "Exact target program name, project path, URL or program_id; ambiguous names fail"),
                "addresses", Map.of(
                    "type", "array",
                    "description", "Array of hex addresses to create functions at (e.g. [\"0x0024d618\", \"0x00287200\"])",
                    "items", Map.of("type", "string", "minLength", 1), "minItems", 1, "maxItems", 10000
                ),
                "dry_run", Map.of("type", "boolean",
                    "description", "If true, validate addresses without creating functions (default false)",
                    "default", false)
            ),
            List.of("target_program", "addresses"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @SuppressWarnings("unchecked")
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                             GhidrAssistMCPBackend backend) {
        return run(arguments, currentProgram, backend, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, ghidrassistmcp.tasks.McpTask task) {
        return run(arguments, currentProgram, backend, task);
    }

    @SuppressWarnings("unchecked")
    private McpSchema.CallToolResult run(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, ghidrassistmcp.tasks.McpTask task) {
        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        String targetProgramName = (String) arguments.get("target_program");
        boolean dryRun = false;
        if (arguments.get("dry_run") instanceof Boolean)
            dryRun = (Boolean) arguments.get("dry_run");

        try (var targetLease = ProgramSelection.lease(backend, targetProgramName, currentProgram)) {
        Program targetProgram = targetLease.program();
        if (targetProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Target program not found: " + targetProgramName)
                .build();
        }

        Object addressesObj = arguments.get("addresses");
        if (!(addressesObj instanceof List)) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("'addresses' must be a JSON array of hex strings")
                .build();
        }

        List<?> rawAddresses = (List<?>) addressesObj;
        if (rawAddresses.isEmpty() || rawAddresses.size() > 10000 || rawAddresses.stream().anyMatch(x -> !(x instanceof String s) || s.isBlank()))
            return ProjectToolSupport.error("addresses must contain 1..10000 nonblank hex strings");
        List<String> addresses = (List<String>) addressesObj;
        if (!dryRun && targetProgram.getCurrentTransactionInfo() != null)
            return ProjectToolSupport.error("Target has an active transaction; retry after it finishes");

        int rolledBack = 0;
        int successCount = 0;
        int alreadyExistsCount = 0;
        int failCount = 0;
        boolean cancelled = false;
        List<String> details = new ArrayList<>();

        int txId = -1;
        if (!dryRun) {
            txId = targetProgram.startTransaction("Create Functions at Addresses");
        }

        try {
            ghidra.util.task.TaskMonitor monitor = task == null ? new ConsoleTaskMonitor()
                : new ghidrassistmcp.tasks.McpTaskMonitor(task, 0, 100, "Create Functions");

            for (String addrStr : addresses) {
                if (monitor.isCancelled() || Thread.currentThread().isInterrupted()) {
                    cancelled = true; details.add("CANCELLED: remaining addresses not processed"); break;
                }
                try {
                    Address addr = targetProgram.getAddressFactory().getAddress(addrStr);
                    if (addr == null) {
                        details.add(String.format("FAIL %s: invalid address", addrStr));
                        failCount++;
                        continue;
                    }

                    // Check if function already exists
                    Function existing = targetProgram.getFunctionManager().getFunctionAt(addr);
                    if (existing != null) {
                        details.add(String.format("SKIP %s: function already exists (%s)",
                            addrStr, existing.getName()));
                        alreadyExistsCount++;
                        continue;
                    }

                    // Check if address is in valid memory
                    if (!targetProgram.getMemory().contains(addr)) {
                        details.add(String.format("FAIL %s: address not in program memory", addrStr));
                        failCount++;
                        continue;
                    }

                    if (dryRun) {
                        details.add(String.format("WOULD CREATE %s: address valid, no existing function",
                            addrStr));
                        successCount++;
                        continue;
                    }

                    // Step 1: Disassemble bytes at the address
                    DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
                    boolean disOk = disCmd.applyTo(targetProgram, monitor);

                    // Step 2: Create function
                    CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
                    boolean funcOk = funcCmd.applyTo(targetProgram, monitor);

                    if (funcOk) {
                        Function created = targetProgram.getFunctionManager().getFunctionAt(addr);
                        String name = created != null ? created.getName() : "unknown";
                        long size = created != null ? created.getBody().getNumAddresses() : 0;
                        details.add(String.format("OK %s: created function %s (%d bytes)",
                            addrStr, name, size));
                        successCount++;
                    } else {
                        String reason = funcCmd.getStatusMsg();
                        if (reason == null || reason.isEmpty()) reason = "CreateFunctionCmd failed";
                        details.add(String.format("FAIL %s: %s (disassemble=%s)",
                            addrStr, reason, disOk ? "ok" : "failed"));
                        failCount++;
                    }

                } catch (Exception e) {
                    details.add(String.format("FAIL %s: %s", addrStr, e.getMessage()));
                    failCount++;
                }
            }

            if (!dryRun && txId >= 0) {
                cancelled |= monitor.isCancelled() || Thread.currentThread().isInterrupted();
                boolean commit = failCount == 0 && !cancelled;
                targetProgram.endTransaction(txId, commit);
                txId = -1;
                if (!commit) {
                    rolledBack = successCount;
                    successCount = 0;
                    details.replaceAll(detail -> detail.startsWith("OK ") ? "ROLLED BACK " + detail.substring(3) : detail);
                }
            }

        } catch (Exception e) {
            if (!dryRun && txId >= 0) {
                targetProgram.endTransaction(txId, false);
            }
            return McpSchema.CallToolResult.builder()
                .addTextContent("Transaction failed: " + e.getMessage())
                .build();
        }

        // Format report
        StringBuilder result = new StringBuilder();
        result.append("Create Functions at Addresses Report\n");
        result.append("====================================\n");
        result.append("Target: ").append(targetProgramName).append("\n");
        if (dryRun) result.append("MODE: DRY RUN (no changes applied)\n");
        result.append("\n");
        result.append("Total addresses: ").append(addresses.size()).append("\n");
        result.append("Created: ").append(successCount).append("\n");
        result.append("Rolled back: ").append(rolledBack).append("\n");
        result.append("Already existed: ").append(alreadyExistsCount).append("\n");
        result.append("Failed: ").append(failCount).append("\n\n");

        result.append("Details:\n");
        for (String detail : details) {
            result.append("  ").append(detail).append("\n");
        }

        return McpSchema.CallToolResult.builder().isError(failCount > 0 || cancelled)
            .structuredContent(Map.of("target_program", targetProgramName, "dry_run", dryRun, "created", successCount,
                "rolled_back", rolledBack, "failed", failCount, "skipped", alreadyExistsCount,
                "committed", !dryRun && failCount == 0 && !cancelled, "cancelled", cancelled, "details", details))
            .addTextContent(result.toString())
            .build();
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
    }


}
