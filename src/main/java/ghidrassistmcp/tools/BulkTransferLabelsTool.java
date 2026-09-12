/*
 * MCP tool that bulk-transfers function names and prototypes to a target program.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.lang.Register;
import java.math.BigInteger;
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
               "Opt-in comments, bookmarks, data_types, and register_context annotations default to preview. " +
               "Use after string_anchor_matcher or function_byte_matcher.";
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
                            "prototype", Map.of("type", "string", "description", "Optional: C function prototype/signature"),
                            "comment", Map.of("type", "string", "description", "Optional plate comment at function entry"),
                            "bookmarks", Map.of("type", "array", "description", "Optional bookmarks [{type,category,comment}]", "items", Map.of("type", "object")),
                            "data_types", Map.of("type", "array", "description", "Optional typed data [{address,data_type,array_count}]", "items", Map.of("type", "object")),
                            "register_context", Map.of("type", "array", "description", "Optional context [{register,value,start,end}]", "items", Map.of("type", "object"))
                        ),
                        "required", List.of("target_addr", "name")
                    )
                ),
                "target_program", Map.of("type", "string", "description", "Exact target program name, project path, URL or program_id; ambiguous names fail"),
                "dry_run", Map.of("type", "boolean", "description", "If true, validate without applying changes (default false)", "default", false),
                "conflict_policy", Map.of("type", "string", "enum", List.of("preserve", "replace", "error"), "default", "preserve", "description", "Policy for opt-in annotation conflicts"),
                "preview_annotations", Map.of("type", "boolean", "description", "Preview opt-in annotations without applying (default true when annotations are present)", "default", true)
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
        String requestedTarget = arguments.get("target_program") instanceof String ? (String)arguments.get("target_program") : null;
        String targetProgramName = requestedTarget;
        boolean dryRun = false;
        if (arguments.get("dry_run") instanceof Boolean)
            dryRun = (Boolean) arguments.get("dry_run");
        String conflictPolicy = arguments.get("conflict_policy") instanceof String ? (String)arguments.get("conflict_policy") : "preserve";
        try { AnnotationTransferSupport.parsePolicy(conflictPolicy); }
        catch (IllegalArgumentException e) { return McpSchema.CallToolResult.builder().isError(true).addTextContent(e.getMessage()).build(); }

        try (var targetLease = ProgramSelection.lease(backend, targetProgramName, currentProgram)) {
        Program targetProgram = targetLease.program();
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

        List<?> rawTransfers = (List<?>) transfersObj;
        List<Map<String, Object>> transfers = new ArrayList<>();
        boolean hasAnnotations = false;
        for (int i = 0; i < rawTransfers.size(); i++) {
            Object raw = rawTransfers.get(i);
            if (!(raw instanceof Map<?, ?>)) {
                return McpSchema.CallToolResult.builder().isError(true)
                    .addTextContent("Transfer #" + (i + 1) + " must be an object").build();
            }
            @SuppressWarnings("unchecked") Map<String, Object> row = (Map<String, Object>) raw;
            transfers.add(row);
            hasAnnotations |= row.containsKey("comment") || row.containsKey("bookmarks")
                || row.containsKey("data_types") || row.containsKey("register_context");
        }
        Boolean requestedPreview = arguments.get("preview_annotations") instanceof Boolean ? (Boolean)arguments.get("preview_annotations") : null;
        boolean previewAnnotations = AnnotationTransferSupport.previewByDefault(hasAnnotations, requestedPreview, dryRun);
        // A caller must explicitly opt in to annotation mutation; dry_run always wins.
        boolean applyAnnotations = !dryRun && !previewAnnotations;
        boolean atomicAnnotations = hasAnnotations && !previewAnnotations && !dryRun;

        int successCount = 0;
        int failCount = 0;
        int skipCount = 0;
        List<String> errors = new ArrayList<>();
        List<Map<String, Object>> itemResults = new ArrayList<>();

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
                    if (atomicAnnotations) throw new IllegalStateException(String.format("#%d: missing target_addr or name", i + 1));
                    errors.add(String.format("#%d: missing target_addr or name", i + 1));
                    itemResults.add(Map.of("index", i, "status", "error", "message", "missing target_addr or name"));
                    failCount++;
                    continue;
                }

                try {
                    Address addr = targetProgram.getAddressFactory().getAddress(targetAddr);
                    if (addr == null) {
                        if (atomicAnnotations) throw new IllegalStateException(String.format("#%d: invalid address %s", i + 1, targetAddr));
                        errors.add(String.format("#%d: invalid address %s", i + 1, targetAddr));
                        itemResults.add(Map.of("index", i, "status", "error", "message", "invalid address"));
                        failCount++;
                        continue;
                    }

                    Function func = targetProgram.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        // Try to find function containing this address
                        func = targetProgram.getFunctionManager().getFunctionContaining(addr);
                        if (func == null) {
                            if (atomicAnnotations) throw new IllegalStateException(String.format("#%d: no function at %s (%s)", i + 1, targetAddr, name));
                            errors.add(String.format("#%d: no function at %s (%s)", i + 1, targetAddr, name));
                            itemResults.add(Map.of("index", i, "status", "error", "message", "no function"));
                            failCount++;
                            continue;
                        }
                    }

                    boolean sameName = func.getName().equals(name);

                    if (!dryRun && !sameName) {
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

                    AnnotationResult annotation = validateOrApplyAnnotations(targetProgram, func, entry, conflictPolicy, applyAnnotations);
                    if (annotation.error != null) {
                        // Annotation conflicts are transaction-fatal: do not leave an
                        // earlier annotation from this batch committed accidentally.
                        throw new IllegalStateException(String.format("#%d: %s", i + 1, annotation.error));
                    }
                    if (sameName && annotation.changed == false) skipCount++;
                    else successCount++;
                    itemResults.add(Map.of("index", i, "status", sameName && !annotation.changed ? "skipped" : "success",
                        "address", targetAddr, "name", name, "annotations", annotation.changed));

                } catch (Exception e) {
                    if (atomicAnnotations) throw new IllegalStateException(String.format("#%d: %s - %s", i + 1, name, e.getMessage()), e);
                    errors.add(String.format("#%d: %s - %s", i + 1, name, e.getMessage()));
                    itemResults.add(Map.of("index", i, "status", "error", "message", String.valueOf(e.getMessage())));
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
            return McpSchema.CallToolResult.builder().isError(true)
                .addTextContent("Transaction failed; all changes rolled back: " + e.getMessage())
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
        if (hasAnnotations) result.append("Annotations: ").append(applyAnnotations ? "APPLIED" : "PREVIEW").append(" (policy: ").append(conflictPolicy).append(")\n");

        if (!errors.isEmpty()) {
            result.append("\nErrors:\n");
            for (String err : errors) {
                result.append("  - ").append(err).append("\n");
            }
        }

        return McpSchema.CallToolResult.builder()
            .structuredContent(Map.of("target_program", targetProgramName, "dry_run", dryRun,
                "successful", successCount, "skipped", skipCount, "failed", failCount,
                "items", itemResults))
            .addTextContent(result.toString())
            .build();
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
    }



    @SuppressWarnings("unchecked")
    private AnnotationResult validateOrApplyAnnotations(Program p, Function f, Map<String,Object> e,
                                                         String policy, boolean apply) {
        try {
            boolean changed = false;
            String comment = e.get("comment") instanceof String ? (String)e.get("comment") : null;
            if (comment != null) {
                String old = f.getComment();
                if (old != null && !old.equals(comment)) {
                    if ("error".equals(policy)) return new AnnotationResult(false, "comment conflict at " + f.getEntryPoint());
                    if ("replace".equals(policy) && apply) f.setComment(comment);
                    changed = "replace".equals(policy);
                } else if (old == null) { if (apply) f.setComment(comment); changed = true; }
            }
            Object bm = e.get("bookmarks");
            if (bm != null && !(bm instanceof List)) return new AnnotationResult(false, "bookmarks must be an array");
            if (bm instanceof List) for (Object raw : (List<?>)bm) {
                if (!(raw instanceof Map<?, ?>)) return new AnnotationResult(false, "bookmark entry must be an object");
                Map<String,Object> b = (Map<String,Object>) raw;
                String type = b.get("type") instanceof String ? (String)b.get("type") : BookmarkType.NOTE;
                String category = b.get("category") instanceof String ? (String)b.get("category") : "Analysis";
                String text = b.get("comment") instanceof String ? (String)b.get("comment") : "MCP annotation";
                var existing = p.getBookmarkManager().getBookmark(f.getEntryPoint(), type, category);
                if (existing != null && !existing.getComment().equals(text)) {
                    if ("error".equals(policy)) return new AnnotationResult(false, "bookmark conflict at " + f.getEntryPoint());
                    if ("preserve".equals(policy)) continue;
                    if (apply) p.getBookmarkManager().removeBookmark(existing);
                }
                if (apply) p.getBookmarkManager().setBookmark(f.getEntryPoint(), type, category, text);
                changed = true;
            }
            Object dts = e.get("data_types");
            if (dts != null && !(dts instanceof List)) return new AnnotationResult(false, "data_types must be an array");
            if (dts instanceof List) for (Object raw : (List<?>)dts) {
                if (!(raw instanceof Map<?, ?>)) return new AnnotationResult(false, "data_types entry must be an object");
                Map<String,Object> d = (Map<String,Object>) raw;
                String as = d.get("address") instanceof String ? (String)d.get("address") : f.getEntryPoint().toString();
                String tn = d.get("data_type") instanceof String ? (String)d.get("data_type") : null;
                if (tn == null) return new AnnotationResult(false, "data_types entry missing data_type");
                DataTypeResolver.Result resolved = DataTypeResolver.resolve(p.getDataTypeManager(), tn, d.get("array_count"));
                if (resolved.isError()) return new AnnotationResult(false, resolved.errorMessage);
                Address a = p.getAddressFactory().getAddress(as);
                if (a == null) return new AnnotationResult(false, "invalid data_types address " + as);
                DataType dt = resolved.dataType;
                if (dt.getLength() < 1 || dt.getLength() > 1048576)
                    return new AnnotationResult(false, "data type must have a fixed length of 1..1048576 bytes");
                Address last = a.addNoWrap(dt.getLength() - 1);
                if (!p.getMemory().contains(a, last)) return new AnnotationResult(false, "data type range is not mapped memory");
                var span = new ghidra.program.model.address.AddressSet(a, last);
                var existing = p.getListing().getDefinedDataAt(a);
                boolean same = existing != null && existing.getLength() == dt.getLength() && existing.getDataType().isEquivalent(dt);
                if (same) continue;
                boolean occupied = p.getListing().getDefinedDataContaining(a) != null
                    || p.getListing().getInstructionContaining(a) != null
                    || p.getListing().getDefinedData(span, true).hasNext()
                    || p.getListing().getInstructions(span, true).hasNext();
                if (occupied) {
                    if ("error".equals(policy)) return new AnnotationResult(false, "data type conflict at " + a);
                    if ("preserve".equals(policy)) continue;
                }
                if (apply) {
                    if (occupied) p.getListing().clearCodeUnits(a, last, false);
                    p.getListing().createData(a, dt);
                }
                changed = true;
            }
            Object rc = e.get("register_context");
            if (rc != null && !(rc instanceof List)) return new AnnotationResult(false, "register_context must be an array");
            if (rc instanceof List) for (Object raw : (List<?>)rc) {
                if (!(raw instanceof Map<?, ?>)) return new AnnotationResult(false, "register_context entry must be an object");
                Map<String,Object> c = (Map<String,Object>) raw;
                String rn = c.get("register") instanceof String ? (String)c.get("register") : null;
                String vs = c.get("value") instanceof String ? (String)c.get("value") : String.valueOf(c.get("value"));
                String ss = c.get("start") instanceof String ? (String)c.get("start") : f.getEntryPoint().toString();
                String es = c.get("end") instanceof String ? (String)c.get("end") : f.getBody().getMaxAddress().toString();
                Register r = p.getProgramContext().getRegister(rn); Address s=p.getAddressFactory().getAddress(ss), end=p.getAddressFactory().getAddress(es);
                if (r == null || s == null || end == null || s.compareTo(end) > 0 || c.get("value") == null)
                    return new AnnotationResult(false, "invalid register_context entry");
                BigInteger requested;
                try { requested = new BigInteger(vs.replaceFirst("(?i)^0x", ""), vs.toLowerCase().startsWith("0x") ? 16 : 10); }
                catch (NumberFormatException ex) { return new AnnotationResult(false, "invalid register_context value"); }
                if (!s.getAddressSpace().equals(end.getAddressSpace()) || requested.signum() < 0 || requested.bitLength() > r.getBitLength())
                    return new AnnotationResult(false, "register context range/value exceeds register bounds");
                var context = p.getProgramContext();
                var intervals = context.getRegisterValueAddressRanges(r, s, end);
                boolean conflict = false;
                int checked = 0;
                while (intervals.hasNext()) {
                    if (++checked > 10000) return new AnnotationResult(false, "register context exceeds 10000 segments");
                    var interval = intervals.next();
                    BigInteger existing = context.getValue(r, interval.getMinAddress(), false);
                    conflict |= existing != null && !existing.equals(requested);
                }
                if (conflict) {
                    if ("error".equals(policy)) return new AnnotationResult(false, "register context conflict at " + s);
                    if ("preserve".equals(policy)) continue;
                }
                if (apply) p.getProgramContext().setValue(r, s, end, requested);
                changed = true;
            }
            return new AnnotationResult(changed, null);
        } catch (Exception ex) { return new AnnotationResult(false, ex.getMessage()); }
    }

    private static final class AnnotationResult { final boolean changed; final String error; AnnotationResult(boolean c,String e){changed=c;error=e;} }
}
