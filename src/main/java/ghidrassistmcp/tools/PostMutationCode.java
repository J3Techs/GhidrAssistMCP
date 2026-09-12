package ghidrassistmcp.tools;

import java.util.LinkedHashMap;
import java.util.Map;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitorAdapter;
import ghidrassistmcp.McpMutationGuard;
import ghidrassistmcp.ProgramIdentity;
import ghidrassistmcp.decompiler.DecompilerService;
import io.modelcontextprotocol.spec.McpSchema;

/** Post-commit verification cannot change the already committed mutation outcome. */
final class PostMutationCode {
    private PostMutationCode() {}

    static String validateOptions(Map<String, Object> args) {
        if (args.containsKey("return_code") && !(args.get("return_code") instanceof Boolean))
            return "return_code must be boolean";
        try {
            QueryPageBounds.integer(args, "max_chars", 20000, 1, 200000);
            QueryPageBounds.integer(args, "verification_timeout_seconds", 10, 1, 300);
        } catch (IllegalArgumentException e) { return e.getMessage(); }
        return null;
    }

    static McpSchema.CallToolResult result(Program program, Function function, String prototype,
            DecompilerService service, Map<String, Object> args) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mutation_status", "committed");
        out.put("verification_status", "unavailable");
        out.put("stored_prototype", prototype);
        try {
            out.put("program_id", program == null ? null : ProgramIdentity.id(program));
            out.put("function_entry", function == null ? null : function.getEntryPoint().toString());
            out.put("function", function == null ? null : function.getName(true));
            if (function != null) out.put("stored_prototype", function.getPrototypeString(false, false));
            if (program == null || function == null || service == null) {
                out.put("verification_diagnostic", "Selected function or decompiler service unavailable");
                return ProjectToolSupport.result(out);
            }
            // Capture before releasing the guard: a later writer must be observable as stale.
            long committed = program.getModificationNumber();
            out.put("committed_revision", committed);
            int maxChars = QueryPageBounds.integer(args, "max_chars", 20000, 1, 200000);
            int timeout = QueryPageBounds.integer(args, "verification_timeout_seconds", 10, 1, 300);
            return McpMutationGuard.afterCommit(program, () -> {
                Thread owner = Thread.currentThread();
                var monitor = new TaskMonitorAdapter(true) {
                    @Override public boolean isCancelled() { return super.isCancelled() || owner.isInterrupted(); }
                };
                try {
                    if (program.getModificationNumber() != committed) {
                        out.put("verification_status", "stale");
                    } else if (monitor.isCancelled()) {
                        out.put("verification_diagnostic", "Verification interrupted after mutation committed");
                    } else {
                        try (var session = service.open(program)) {
                            var decompiled = session.decompiler().decompileFunction(function, timeout, monitor);
                            if (program.getModificationNumber() != committed) {
                                out.put("verification_status", "stale");
                            } else if (monitor.isCancelled()) {
                                out.put("verification_diagnostic", "Verification interrupted after mutation committed");
                            } else if (decompiled != null && decompiled.decompileCompleted()
                                    && decompiled.getDecompiledFunction() != null
                                    && decompiled.getDecompiledFunction().getC() != null) {
                                String code = decompiled.getDecompiledFunction().getC();
                                int end = Math.min(code.length(), maxChars);
                                if (end > 0 && end < code.length() && Character.isHighSurrogate(code.charAt(end - 1))) end--;
                                out.put("code", code.substring(0, end));
                                out.put("code_truncated", end < code.length());
                                out.put("verification_status", "verified");
                            } else {
                                out.put("verification_diagnostic", decompiled == null ? "Decompiler returned no result"
                                    : String.valueOf(decompiled.getErrorMessage()));
                            }
                        }
                    }
                } catch (Exception e) {
                    out.put("verification_diagnostic", e.getClass().getSimpleName() + ": " + e.getMessage());
                }
                out.put("observed_revision", program.getModificationNumber());
                return ProjectToolSupport.result(out);
            });
        } catch (Exception e) {
            out.put("verification_diagnostic", e.getClass().getSimpleName() + ": " + e.getMessage());
            return ProjectToolSupport.result(out);
        }
    }
}
