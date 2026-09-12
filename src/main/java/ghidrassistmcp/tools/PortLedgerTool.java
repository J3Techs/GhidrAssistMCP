package ghidrassistmcp.tools;

import java.util.*;
import java.math.BigDecimal;
import ghidra.program.model.listing.*;
import ghidrassistmcp.*;
import io.modelcontextprotocol.spec.McpSchema;

/** Explicit bounded checkpoint inspection; verification rechecks the stored source, never caller substitutes. */
public final class PortLedgerTool implements McpTool {
    public String getName() { return "port_ledger"; }
    public String getDescription() { return "Inspect PORT provenance or obtain a function fingerprint with get; page list; verify stored source/target fingerprints with expected_target_revision and operation_id. Verification checks annotation/byte identity, not semantic equivalence. Save the target separately."; }
    public boolean isReadOnly() { return false; }
    public boolean isReadOnly(Map<String,Object> args) { return List.of("list", "get").contains(args.get("action")); }
    public McpSchema.JsonSchema getInputSchema() {
        var p = new LinkedHashMap<String,Object>();
        p.put("action", Map.of("type", "string", "enum", List.of("list", "get", "verify")));
        for (String k : List.of("address", "operation_id", "source_program_id", "source_address", "source_fingerprint")) p.put(k, Map.of("type", "string"));
        p.put("expected_target_revision", Map.of("type", List.of("string", "integer"), "description", "Exact modification number from get/list; required for verify"));
        p.put("offset", Map.of("type", "integer", "minimum", 0, "maximum", 10000));
        p.put("limit", Map.of("type", "integer", "minimum", 1, "maximum", 16, "default", 8));
        return new McpSchema.JsonSchema("object", p, List.of("action"), null, null, null);
    }
    public Map<String,Object> getOutputSchema() {
        return Map.of("type", "object", "properties", Map.of("schema_version", Map.of("type", "integer"),
            "action", Map.of("type", "string"), "error", Map.of("type", "string")));
    }
    public McpSchema.CallToolResult execute(Map<String,Object> args, Program program) { return execute(args, program, null); }
    public McpSchema.CallToolResult execute(Map<String,Object> args, Program target, GhidrAssistMCPBackend backend) {
        try {
            if (target == null) throw new IllegalArgumentException("No selected program");
            String action = ProjectToolSupport.required(args, "action");
            long revision = target.getModificationNumber();
            if (args.containsKey("expected_target_revision") && revisionArg(args) != revision) throw new IllegalArgumentException("Target revision changed; inspect again");
            if (action.equals("list")) return list(args, target, revision);
            if (!List.of("get", "verify").contains(action)) throw new IllegalArgumentException("Invalid action");
            var addr = target.getAddressFactory().getAddress(ProjectToolSupport.required(args, "address"));
            Function function = addr == null ? null : target.getFunctionManager().getFunctionAt(addr);
            if (function == null) throw new IllegalArgumentException("An exact function entry is required");
            var row = PortLedger.read(function);
            if (action.equals("get")) {
                var result = base(action, target, revision);
                result.put("address", addr.toString()); result.put("ledger", row);
                result.put("current_fingerprint", PortLedger.fingerprint(function));
                result.put("checkpoint_matches", row != null && result.get("current_fingerprint").equals(row.get("destination_fingerprint")));
                if (target.getModificationNumber() != revision) throw new IllegalArgumentException("Target changed during inspection");
                return ProjectToolSupport.result(result);
            }
            if (backend == null) throw new IllegalArgumentException("Verification requires a backend to resolve the persisted source");
            if (!target.isChangeable()) throw new IllegalArgumentException("Target is not changeable");
            if (revisionArg(args) != revision) throw new IllegalArgumentException("Target revision changed");
            String op = ProjectToolSupport.required(args, "operation_id");
            if (row == null || !op.equals(row.get("operation_id"))) throw new IllegalArgumentException("No matching valid PORT checkpoint");
            Map<?,?> metadata = (Map<?,?>)row.get("source");
            for (String key : List.of("source_program_id", "source_address", "source_fingerprint"))
                if (args.containsKey(key) && !Objects.equals(args.get(key), metadata.get(key))) throw new IllegalArgumentException("Caller source differs from persisted PORT checkpoint");
            String sourceId = (String)metadata.get("source_program_id");
            Program source = ProgramIdentity.resolve(sourceId, backend.getAllOpenPrograms());
            if (!sourceId.equals(ProgramIdentity.id(source))) throw new IllegalArgumentException("Checkpoint source is not an exact persistent program identity");
            Object consumer = new Object();
            if (!source.addConsumer(consumer)) throw new IllegalArgumentException("Source closed");
            try {
                long sourceRevision = source.getModificationNumber();
                var sourceEntry = source.getAddressFactory().getAddress((String)metadata.get("source_address"));
                var sf = sourceEntry == null ? null : source.getFunctionManager().getFunctionAt(sourceEntry);
                if (sf == null || !metadata.get("source_fingerprint").equals(PortLedger.fingerprint(sf))) throw new IllegalArgumentException("Persisted source fingerprint changed");
                if (source.getCurrentTransactionInfo() != null || target.getCurrentTransactionInfo() != null) throw new IllegalArgumentException("Source or target has an active transaction");
                String label = "MCP verify PORT " + UUID.randomUUID();
                int tx = target.startTransaction(label); boolean commit = false;
                try {
                    var info = target.getCurrentTransactionInfo();
                    if (info != null && info.getOpenSubTransactions().stream().anyMatch(d -> !TransferPlanSupport.ownTransactionDescription(d, label))) {
                        commit = true; // close only our nested scope, preserving the foreign writer
                        throw new IllegalArgumentException("Foreign target transaction started; retry inspection");
                    }
                    if (target.getModificationNumber() != revision || source.getModificationNumber() != sourceRevision)
                        throw new IllegalArgumentException("Source or target changed during verification");
                    if (!PortLedger.markVerified(target, function, revision, op)) throw new IllegalArgumentException("Destination checkpoint changed");
                    if (source.getModificationNumber() != sourceRevision || (source != target && source.getCurrentTransactionInfo() != null))
                        throw new IllegalArgumentException("Source changed during verification");
                    commit = true;
                } finally { target.endTransaction(tx, commit); }
                var result = base(action, target, target.getModificationNumber());
                result.put("verified", true); result.put("operation_id", op);
                result.put("verification_scope", "stored source and destination function bytes and annotations");
                result.put("saved", false); return ProjectToolSupport.result(result);
            } finally { if (!source.isClosed() && source.isUsedBy(consumer)) source.release(consumer); }
        } catch (Exception e) {
            return ProjectToolSupport.result(Map.of("schema_version", 1, "error", Objects.toString(e.getMessage(), e.getClass().getSimpleName())), true);
        }
    }
    private McpSchema.CallToolResult list(Map<String,Object> args, Program p, long revision) throws Exception {
        int offset = QueryPageBounds.integer(args, "offset", 0, 0, 10000);
        int limit = QueryPageBounds.integer(args, "limit", 8, 1, 16);
        var entries = new ArrayList<Map<String,Object>>(); int seen = 0; boolean more = false;
        var it = p.getBookmarkManager().getBookmarksIterator("NOTE");
        while (it.hasNext()) {
            if (Thread.currentThread().isInterrupted()) throw new IllegalArgumentException("PORT listing interrupted");
            var b = it.next(); if (!PortLedger.CATEGORY.equals(b.getCategory())) continue;
            if (seen++ < offset) continue;
            if (entries.size() == limit) { more = true; break; }
            var parsed = PortLedger.parse(b.getComment());
            Map<String,Object> entry = new LinkedHashMap<>(); entry.put("address", b.getAddress().toString());
            entry.put("ledger", parsed); entry.put("valid", parsed != null); entries.add(entry);
            if (new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(ProjectToolSupport.result(Map.of("entries", entries))).length > 110000) {
                entries.removeLast(); more = true; break;
            }
        }
        if (p.getModificationNumber() != revision) throw new IllegalArgumentException("Target changed while paging PORT ledger");
        var result = base("list", p, revision); result.put("entries", entries); result.put("count", entries.size());
        result.put("offset", offset); result.put("limit", limit); result.put("has_more", more);
        result.put("next_offset", more ? offset + entries.size() : null);
        return ProjectToolSupport.result(result);
    }
    private static long revisionArg(Map<String,Object> args) {
        Object value = args.get("expected_target_revision");
        if (!(value instanceof String) && !(value instanceof Number)) throw new IllegalArgumentException("expected_target_revision is required");
        try { long v = new BigDecimal(value.toString()).longValueExact(); if (v < 0) throw new ArithmeticException(); return v; }
        catch (NumberFormatException | ArithmeticException e) { throw new IllegalArgumentException("expected_target_revision must be an exact nonnegative integer"); }
    }
    private static LinkedHashMap<String,Object> base(String action, Program p, long revision) {
        var result = new LinkedHashMap<String,Object>(); result.put("schema_version", 1); result.put("action", action);
        result.put("program_id", ProgramIdentity.id(p)); result.put("modification_number", Long.toString(revision)); return result;
    }
}
