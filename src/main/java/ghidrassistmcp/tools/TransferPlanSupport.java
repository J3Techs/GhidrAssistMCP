package ghidrassistmcp.tools;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Shared transfer-plan helpers for {@code bulk_transfer_labels}.
 *
 * <p>COMPATIBILITY: {@code name_policy} and {@code signature_policy} default to
 * {@code default_only}. Analyst-origin values (USER_DEFINED, IMPORTED, ANALYSIS)
 * are preserved unless {@code replace} is requested. DEFAULT-origin values are
 * updated. This matches BSim's overwrite-or-DEFAULT rule and is a change from
 * the previous always-overwrite name behavior.
 *
 * <p>Preview tokens are SHA-256 fingerprints of the current validated plan
 * binding; there is no preview registry.
 */
final class TransferPlanSupport {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String TOOL = "bulk_transfer_labels";
    /** One snapshot per request; copying the live catalog per row is unbounded. */
    static final int MAX_STAGED_TYPES = 10_000;
    static final int MAX_TRANSFERS = 500;

    enum FieldPolicy { DEFAULT_ONLY, REPLACE }
    enum Intent { APPLY, PRESERVE, SKIP, FAIL }
    enum Outcome { COMMITTED, PRESERVED, SKIPPED, FAILED, ROLLED_BACK, WOULD_COMMIT, PREVIEWED }

    private TransferPlanSupport() { }

    static FieldPolicy parseFieldPolicy(String value, String parameter) {
        if (value == null || value.isBlank() || "default_only".equalsIgnoreCase(value.trim())) {
            return FieldPolicy.DEFAULT_ONLY;
        }
        if ("replace".equalsIgnoreCase(value.trim())) return FieldPolicy.REPLACE;
        throw new IllegalArgumentException(parameter + " must be default_only or replace");
    }

    static FieldPolicy fieldPolicyArg(Map<String, Object> arguments, String parameter) {
        if (!arguments.containsKey(parameter) || arguments.get(parameter) == null) return FieldPolicy.DEFAULT_ONLY;
        Object value = arguments.get(parameter);
        if (!(value instanceof String string)) {
            throw new IllegalArgumentException(parameter + " must be a string (default_only or replace)");
        }
        return parseFieldPolicy(string, parameter);
    }

    /** Absent uses fallback. A non-boolean value (including the string "true") is an error, not coercion. */
    static boolean booleanArg(Map<String, Object> arguments, String key, boolean fallback) {
        if (!arguments.containsKey(key) || arguments.get(key) == null) return fallback;
        Object value = arguments.get(key);
        if (value instanceof Boolean bool) return bool;
        throw new IllegalArgumentException(key + " must be a boolean");
    }

    static String optionalStringArg(Map<String, Object> arguments, String key) {
        if (!arguments.containsKey(key) || arguments.get(key) == null) return null;
        Object value = arguments.get(key);
        if (value instanceof String string) return string;
        throw new IllegalArgumentException(key + " must be a string");
    }

    static String requiredStringField(Object value, String field) {
        if (!(value instanceof String string) || string.isBlank()) {
            throw new IllegalArgumentException(field + " must be a non-blank string");
        }
        return string;
    }

    /**
     * True when {@code description} is this call's transaction or Ghidra's native
     * wrapping of it. ProgramDB reports the exact startTransaction string; some
     * builds prefix {@code ": "}. Empty {@code ": "} suffixes are native wrappers,
     * not a second writer.
     */
    static boolean ownTransactionDescription(String description, String txDescription) {
        if (description == null || txDescription == null || txDescription.isBlank()) return false;
        if (description.equals(txDescription)) return true;
        if (description.endsWith(": " + txDescription)) return true;
        if (description.endsWith(txDescription)) return true;
        return description.endsWith(": ");
    }

    static String policyName(FieldPolicy policy) {
        return policy == FieldPolicy.REPLACE ? "replace" : "default_only";
    }

    /** True for DEFAULT-origin values; null/blank is treated as DEFAULT. */
    static boolean isDefaultOrigin(String source) {
        return source == null || source.isBlank() || "DEFAULT".equalsIgnoreCase(source.trim());
    }

    /**
     * BSim-style field decision: apply when replace is requested or the current
     * value is DEFAULT-origin. Same current/requested values skip. Missing
     * requests skip. Analyst USER_DEFINED/IMPORTED/ANALYSIS values are preserved
     * under default_only.
     */
    static Intent decideField(boolean requested, String requestedValue, String currentValue,
            String provenance, FieldPolicy policy) {
        if (!requested) return Intent.SKIP;
        if (requestedValue != null && requestedValue.equals(currentValue)) return Intent.SKIP;
        if (policy == FieldPolicy.REPLACE || isDefaultOrigin(provenance)) return Intent.APPLY;
        return Intent.PRESERVE;
    }

    static String name(Enum<?> value) {
        return value == null ? null : value.name().toLowerCase(Locale.ROOT);
    }

    static Outcome dryRunOutcome(Intent intent) {
        return switch (intent) {
            case APPLY -> Outcome.WOULD_COMMIT;
            case PRESERVE -> Outcome.PRESERVED;
            case SKIP -> Outcome.SKIPPED;
            case FAIL -> Outcome.FAILED;
        };
    }

    static Outcome applyOutcome(Intent intent) {
        return switch (intent) {
            case APPLY -> Outcome.COMMITTED;
            case PRESERVE -> Outcome.PRESERVED;
            case SKIP -> Outcome.SKIPPED;
            case FAIL -> Outcome.FAILED;
        };
    }

    static ParseOutcome parseNotRequested() {
        return new ParseOutcome("not_requested", null, false);
    }

    static ParseOutcome parseOk(String prototype) {
        return new ParseOutcome("ok", null, false);
    }

    /** Isolated parse failures never report live type changes. */
    static ParseOutcome parseFailure(String error) {
        return new ParseOutcome("failed", error == null ? "prototype parse failed" : error, false);
    }

    /**
     * One bounded type snapshot per request. Callers must reuse this for every
     * prototype parse in the same bulk_transfer_labels invocation.
     */
    static final class StagingSnapshot implements AutoCloseable {
        private final StandAloneDataTypeManager dtm;
        private boolean closed;
        final int copiedTypes;

        StagingSnapshot(StandAloneDataTypeManager dtm, int copiedTypes) {
            this.dtm = dtm;
            this.copiedTypes = copiedTypes;
        }

        DataTypeManager manager() { return dtm; }

        @Override public void close() {
            if (closed) return;
            closed = true;
            dtm.close();
        }
    }

    static StagingSnapshot openStaging(DataTypeManager live, TaskMonitor monitor) {
        if (live == null) throw new IllegalArgumentException("no data type manager for prototype parse");
        StandAloneDataTypeManager staging = new StandAloneDataTypeManager(
            "transfer-plan-staging", live.getDataOrganization());
        int tx = staging.startTransaction("Isolated type snapshot");
        boolean commit = false;
        int copied = 0;
        try {
            var types = live.getAllDataTypes();
            while (types.hasNext()) {
                if (monitor != null && monitor.isCancelled()) {
                    throw new IllegalStateException("Isolated type snapshot cancelled");
                }
                if (copied >= MAX_STAGED_TYPES) {
                    throw new IllegalArgumentException("Target data type catalog exceeds " + MAX_STAGED_TYPES
                        + " types; isolated prototype parse uses one bounded snapshot per request");
                }
                staging.addDataType(types.next(), DataTypeConflictHandler.KEEP_HANDLER);
                copied++;
            }
            commit = true;
            return new StagingSnapshot(staging, copied);
        } finally {
            staging.endTransaction(tx, commit);
            if (!commit) staging.close();
        }
    }

    /** Parse against an existing per-request snapshot. Does not copy the live catalog. */
    static ParseOutcome parsePrototypeIsolated(StagingSnapshot snapshot, String prototype) {
        if (prototype == null || prototype.isBlank()) return parseNotRequested();
        if (snapshot == null || snapshot.manager() == null) return parseFailure("no staging snapshot");
        try {
            FunctionDefinitionDataType parsed = parseSignature(snapshot.manager(), prototype);
            if (parsed != null) return parseOk(prototype);
            return parseFailure("Prototype did not parse as a function signature");
        } catch (Exception e) {
            return parseFailure(e.getMessage());
        }
    }

    /** Test/single-parse helper: opens one snapshot, parses, then closes it. */
    static ParseOutcome parsePrototypeIsolated(DataTypeManager live, String prototype) {
        if (prototype == null || prototype.isBlank()) return parseNotRequested();
        try (StagingSnapshot snapshot = openStaging(live, TaskMonitor.DUMMY)) {
            return parsePrototypeIsolated(snapshot, prototype);
        } catch (Exception e) {
            return parseFailure(e.getMessage());
        }
    }

    private static FunctionDefinitionDataType parseSignature(DataTypeManager staging, String prototype)
            throws Exception {
        try {
            FunctionSignatureParser parser = new FunctionSignatureParser(staging, null);
            FunctionDefinitionDataType sig = parser.parse(null, prototype);
            if (sig != null) return sig;
        } catch (Exception ignored) {
            // Fall through to CParser on the same isolated manager.
        }
        String normalized = prototype.trim();
        if (!normalized.endsWith(";")) normalized += ";";
        CParser parser = new CParser(staging, false, new DataTypeManager[0]);
        DataType parsed = parser.parse(normalized);
        if (parsed instanceof FunctionDefinitionDataType definition) return definition;
        if (parsed instanceof FunctionDefinition definition) {
            return new FunctionDefinitionDataType(definition, staging);
        }
        return null;
    }

    static boolean nativeCommandFailed(boolean applyToResult, String statusMsg) {
        if (!applyToResult) return true;
        return statusIndicatesError(statusMsg);
    }

    static boolean statusIndicatesError(String statusMsg) {
        if (statusMsg == null || statusMsg.isBlank()) return false;
        String s = statusMsg.trim().toLowerCase(Locale.ROOT);
        return s.contains("error") || s.contains("fail");
    }

    static String nativeCommandMessage(boolean applyToResult, String statusMsg) {
        if (statusMsg != null && !statusMsg.isBlank()) return statusMsg;
        return applyToResult ? "function signature command reported an error" : "ApplyFunctionSignatureCmd returned false";
    }

    static Map<String, Object> previewBinding(String programId, String programInstance,
            long modificationNumber, FieldPolicy namePolicy, FieldPolicy signaturePolicy,
            String conflictPolicy, boolean previewAnnotations, List<Map<String, Object>> operations) {
        Map<String, Object> binding = new LinkedHashMap<>();
        binding.put("tool", TOOL);
        binding.put("program_id", programId == null ? "" : programId);
        binding.put("program_instance", programInstance == null ? "" : programInstance);
        binding.put("modification_number", Long.toString(modificationNumber));
        binding.put("name_policy", policyName(namePolicy));
        binding.put("signature_policy", policyName(signaturePolicy));
        binding.put("conflict_policy", conflictPolicy == null ? "preserve" : conflictPolicy);
        binding.put("preview_annotations", previewAnnotations);
        binding.put("operations", normalizeOperations(operations));
        return binding;
    }

    static List<Map<String, Object>> normalizeOperations(List<Map<String, Object>> operations) {
        List<Map<String, Object>> out = new ArrayList<>();
        if (operations == null) return out;
        for (Map<String, Object> operation : operations) {
            out.add(normalizeMap(operation));
        }
        return out;
    }

    static Map<String, Object> normalizeMap(Map<String, Object> raw) {
        Map<String, Object> ordered = new LinkedHashMap<>();
        if (raw == null) return ordered;
        putNormalized(ordered, raw, "target_addr");
        putNormalized(ordered, raw, "name");
        putNormalized(ordered, raw, "prototype");
        putNormalized(ordered, raw, "comment");
        putNormalized(ordered, raw, "bookmarks");
        putNormalized(ordered, raw, "data_types");
        putNormalized(ordered, raw, "register_context");
        putNormalized(ordered, raw, "port_metadata");
        return ordered;
    }

    private static void putNormalized(Map<String, Object> dest, Map<String, Object> raw, String key) {
        if (!raw.containsKey(key) || raw.get(key) == null) return;
        dest.put(key, normalizeValue(raw.get(key)));
    }

    static Object normalizeValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() instanceof String key) sorted.put(key, normalizeValue(entry.getValue()));
            }
            return sorted;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object item : list) out.add(normalizeValue(item));
            return out;
        }
        return value;
    }

    static String fingerprint(Map<String, Object> binding) {
        try {
            return sha256Hex(JSON.writeValueAsBytes(binding));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fingerprint transfer plan: " + e.getMessage(), e);
        }
    }

    static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by the Java runtime", e);
        }
    }

    static boolean tokenSupplied(String token) {
        return token != null && !token.isBlank();
    }

    static boolean tokenMatches(String supplied, String computed) {
        if (!tokenSupplied(supplied)) return true;
        return computed != null && computed.equalsIgnoreCase(supplied.trim());
    }

    static void verifyPreviewToken(String supplied, String computed) {
        if (!tokenMatches(supplied, computed)) {
            throw new IllegalStateException("Stale preview_token; re-preview the current target plan");
        }
    }

    static Map<String, Object> counts(int committed, int wouldCommit, int preserved, int skipped, int failed, int rolledBack) {
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("committed", committed);
        counts.put("would_commit", wouldCommit);
        counts.put("preserved", preserved);
        counts.put("skipped", skipped);
        counts.put("failed", failed);
        counts.put("rolled_back", rolledBack);
        return counts;
    }

    static Map<String, Object> wholeCallRollbackCounts(int rolledBack, int failed, int preserved, int skipped) {
        return counts(0, 0, preserved, skipped, failed, rolledBack);
    }

    static Map<String, Object> countsFromRows(List<PlanRow> rows) {
        int committed = 0, wouldCommit = 0, preserved = 0, skipped = 0, failed = 0, rolledBack = 0;
        if (rows != null) {
            for (PlanRow row : rows) {
                switch (row.status == null ? "" : row.status) {
                    case "committed" -> committed++;
                    case "would_commit" -> wouldCommit++;
                    case "preserved" -> preserved++;
                    case "skipped" -> skipped++;
                    case "failed" -> failed++;
                    case "rolled_back" -> rolledBack++;
                    default -> { }
                }
            }
        }
        return counts(committed, wouldCommit, preserved, skipped, failed, rolledBack);
    }

    static void assignDryRunOutcomes(List<PlanRow> rows) {
        if (rows == null) return;
        for (PlanRow row : rows) {
            row.nameOutcome = dryRunOutcome(row.nameIntent);
            row.signatureOutcome = dryRunOutcome(row.signatureIntent);
            if (row.previewAnnotations && row.annotationChanged && row.annotationIntent != Intent.FAIL) {
                row.annotationOutcome = Outcome.PREVIEWED;
            } else {
                row.annotationOutcome = dryRunOutcome(row.annotationIntent);
            }
            row.status = rowStatus(row);
        }
    }

    static void assignApplyOutcomes(List<PlanRow> rows) {
        if (rows == null) return;
        for (PlanRow row : rows) {
            row.nameOutcome = applyOutcome(row.nameIntent);
            row.signatureOutcome = applyOutcome(row.signatureIntent);
            row.annotationOutcome = applyOutcome(row.annotationIntent);
            row.status = rowStatus(row);
        }
    }

    static void markWholeCallRollback(List<PlanRow> rows, int failedIndex, String error) {
        if (rows == null) return;
        for (int i = 0; i < rows.size(); i++) {
            PlanRow row = rows.get(i);
            if (i == failedIndex) {
                row.error = error;
                rollbackField(row, true);
                row.status = "failed";
            } else if (i < failedIndex) {
                rollbackField(row, false);
                if (row.hadApplyIntent()) row.status = "rolled_back";
                else row.status = rowStatus(row);
            } else {
                if (row.nameIntent == Intent.APPLY) row.nameOutcome = Outcome.SKIPPED;
                if (row.signatureIntent == Intent.APPLY) row.signatureOutcome = Outcome.SKIPPED;
                if (row.annotationIntent == Intent.APPLY) row.annotationOutcome = Outcome.SKIPPED;
                if (row.status == null || "would_commit".equals(row.status) || "committed".equals(row.status)) {
                    row.status = row.failed() ? "failed" : "skipped";
                }
            }
        }
    }

    private static void rollbackField(PlanRow row, boolean failedRow) {
        Outcome applied = failedRow ? Outcome.FAILED : Outcome.ROLLED_BACK;
        if (row.nameIntent == Intent.APPLY) row.nameOutcome = applied;
        else row.nameOutcome = applyOutcome(row.nameIntent);
        if (row.signatureIntent == Intent.APPLY) row.signatureOutcome = applied;
        else row.signatureOutcome = applyOutcome(row.signatureIntent);
        if (row.annotationIntent == Intent.APPLY) row.annotationOutcome = applied;
        else row.annotationOutcome = applyOutcome(row.annotationIntent);
    }

    static void abortBeforeMutation(List<PlanRow> rows) {
        if (rows == null) return;
        for (PlanRow row : rows) {
            row.nameOutcome = row.nameIntent == Intent.APPLY ? Outcome.SKIPPED : applyOutcome(row.nameIntent);
            row.signatureOutcome = row.signatureIntent == Intent.APPLY ? Outcome.SKIPPED : applyOutcome(row.signatureIntent);
            row.annotationOutcome = row.annotationIntent == Intent.APPLY ? Outcome.SKIPPED : applyOutcome(row.annotationIntent);
            row.status = row.failed() ? "failed" : rowStatus(row);
        }
    }

    static String rowStatus(PlanRow row) {
        if (row.failed() || row.nameIntent == Intent.FAIL || row.signatureIntent == Intent.FAIL
                || row.annotationIntent == Intent.FAIL
                || row.nameOutcome == Outcome.FAILED || row.signatureOutcome == Outcome.FAILED
                || row.annotationOutcome == Outcome.FAILED) {
            return "failed";
        }
        if (row.nameOutcome == Outcome.ROLLED_BACK || row.signatureOutcome == Outcome.ROLLED_BACK
                || row.annotationOutcome == Outcome.ROLLED_BACK) {
            return "rolled_back";
        }
        if (row.nameOutcome == Outcome.COMMITTED || row.signatureOutcome == Outcome.COMMITTED
                || row.annotationOutcome == Outcome.COMMITTED) {
            return "committed";
        }
        if (row.nameOutcome == Outcome.WOULD_COMMIT || row.signatureOutcome == Outcome.WOULD_COMMIT
                || row.annotationOutcome == Outcome.WOULD_COMMIT) {
            return "would_commit";
        }
        if (row.nameIntent == Intent.PRESERVE || row.signatureIntent == Intent.PRESERVE
                || row.annotationIntent == Intent.PRESERVE
                || row.nameOutcome == Outcome.PRESERVED || row.signatureOutcome == Outcome.PRESERVED
                || row.annotationOutcome == Outcome.PRESERVED) {
            return "preserved";
        }
        return "skipped";
    }

    static boolean anyApplyIntent(List<PlanRow> rows) {
        if (rows == null) return false;
        for (PlanRow row : rows) if (row.hadApplyIntent()) return true;
        return false;
    }

    static boolean anyPlanFailure(List<PlanRow> rows) {
        if (rows == null) return false;
        for (PlanRow row : rows) if (row.failed()) return true;
        return false;
    }

    static List<Map<String, Object>> itemMaps(List<PlanRow> rows) {
        List<Map<String, Object>> items = new ArrayList<>();
        if (rows == null) return items;
        for (PlanRow row : rows) items.add(row.toMap());
        return items;
    }

    static List<Map<String, Object>> errorMaps(List<PlanRow> rows, String callError) {
        List<Map<String, Object>> errors = new ArrayList<>();
        if (callError != null && !callError.isBlank()) {
            Map<String, Object> call = new LinkedHashMap<>();
            call.put("index", -1);
            call.put("message", callError);
            errors.add(call);
        }
        if (rows != null) {
            for (PlanRow row : rows) {
                if (row.error != null && !row.error.isBlank()) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("index", row.index);
                    item.put("message", row.error);
                    errors.add(item);
                }
            }
        }
        return errors;
    }

    static boolean typesChanged(List<PlanRow> rows) {
        if (rows == null) return false;
        for (PlanRow row : rows) {
            if (row.parse != null && row.parse.typesChanged) return true;
            if (row.signatureOutcome == Outcome.COMMITTED) return true;
        }
        return false;
    }

    static String toJson(Map<String, Object> data) throws Exception {
        return JSON.writeValueAsString(data);
    }

    static McpSchema.CallToolResult callResult(Map<String, Object> data, String json, boolean isError) {
        return McpSchema.CallToolResult.builder().isError(isError).structuredContent(data)
            .addTextContent(json).build();
    }

    static McpSchema.CallToolResult result(Map<String, Object> data, boolean isError) {
        try {
            return callResult(data, toJson(data), isError);
        } catch (Exception e) {
            return ProjectToolSupport.error(e.getMessage() == null ? "Transfer plan serialization failed" : e.getMessage());
        }
    }

    static Map<String, Object> payload(String targetProgram, boolean dryRun, String programId,
            String programInstance, long modificationNumber, FieldPolicy namePolicy,
            FieldPolicy signaturePolicy, String conflictPolicy, boolean previewAnnotations,
            String previewToken, List<PlanRow> rows, String callError, String mutation) {
        Map<String, Object> counts = countsFromRows(rows);
        int successful = ((Number) counts.get("committed")).intValue();
        if (dryRun && counts.get("would_commit") instanceof Number would) successful = would.intValue();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("target_program", targetProgram);
        out.put("dry_run", dryRun);
        out.put("program_id", programId);
        out.put("program_instance", programInstance);
        out.put("modification_number", Long.toString(modificationNumber));
        out.put("name_policy", policyName(namePolicy));
        out.put("signature_policy", policyName(signaturePolicy));
        out.put("conflict_policy", conflictPolicy);
        out.put("preview_annotations", previewAnnotations);
        out.put("preview_token", previewToken);
        out.put("mutation", mutation == null ? "none" : mutation);
        out.put("types_changed", typesChanged(rows));
        out.put("counts", counts);
        out.put("successful", successful);
        out.put("skipped", counts.get("skipped"));
        out.put("failed", counts.get("failed"));
        out.put("items", itemMaps(rows));
        out.put("errors", errorMaps(rows, callError));
        if (callError != null) out.put("error", callError);
        return out;
    }

    static Map<String, Object> outputSchema() {
        Map<String, Object> countProps = new LinkedHashMap<>();
        countProps.put("committed", nonnegative());
        countProps.put("would_commit", nonnegative());
        countProps.put("preserved", nonnegative());
        countProps.put("skipped", nonnegative());
        countProps.put("failed", nonnegative());
        countProps.put("rolled_back", nonnegative());
        Map<String, Object> counts = object(countProps,
            "committed", "would_commit", "preserved", "skipped", "failed", "rolled_back");
        Map<String, Object> parse = object(properties(
            "status", enums("ok", "failed", "not_requested"),
            "error", nullableText(),
            "types_changed", bool()
        ), "status", "types_changed");
        Map<String, Object> fields = object(properties(
            "name", text(),
            "signature", text(),
            "annotations", text()
        ), "name", "signature", "annotations");
        Map<String, Object> item = object(properties(
            "index", nonnegative(),
            "target_addr", text(),
            "entry", nullableText(),
            "function", nullableText(),
            "requested_name", nullableText(),
            "current_name", nullableText(),
            "name_source", nullableText(),
            "requested_signature", nullableText(),
            "current_signature", nullableText(),
            "signature_source", nullableText(),
            "prototype_parse", parse,
            "annotation_conflicts", nullableText(),
            "intended", fields,
            "outcomes", fields,
            "status", text(),
            "error", nullableText()
        ), "index", "target_addr", "status");
        Map<String, Object> errorItem = object(properties(
            "index", Map.of("type", "integer"),
            "message", text()
        ), "index", "message");
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("target_program", text());
        props.put("dry_run", bool());
        props.put("program_id", nullableText());
        props.put("program_instance", nullableText());
        props.put("modification_number", text());
        props.put("name_policy", enums("default_only", "replace"));
        props.put("signature_policy", enums("default_only", "replace"));
        props.put("conflict_policy", enums("preserve", "replace", "error"));
        props.put("preview_annotations", bool());
        props.put("preview_token", Map.of("type", "string", "pattern", "^[0-9a-f]{64}$"));
        props.put("mutation", enums("none", "committed", "rolled_back"));
        props.put("types_changed", bool());
        props.put("counts", counts);
        props.put("successful", nonnegative());
        props.put("skipped", nonnegative());
        props.put("failed", nonnegative());
        props.put("items", Map.of("type", "array", "items", item));
        props.put("errors", Map.of("type", "array", "items", errorItem));
        props.put("error", nullableText());
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", props);
        schema.put("required", List.of("target_program", "dry_run", "items", "counts", "preview_token",
            "name_policy", "signature_policy", "types_changed"));
        schema.put("additionalProperties", true);
        return schema;
    }

    private static Map<String, Object> object(Map<String, Object> properties, String... required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("required", List.of(required));
        schema.put("additionalProperties", true);
        return schema;
    }

    private static Map<String, Object> properties(Object... entries) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) result.put((String) entries[i], entries[i + 1]);
        return result;
    }

    private static Map<String, Object> text() { return Map.of("type", "string"); }
    private static Map<String, Object> bool() { return Map.of("type", "boolean"); }
    private static Map<String, Object> nonnegative() { return Map.of("type", "integer", "minimum", 0); }
    private static Map<String, Object> nullableText() { return Map.of("type", List.of("string", "null")); }
    private static Map<String, Object> enums(String... values) {
        return Map.of("type", "string", "enum", List.of(values));
    }

    static final class ParseOutcome {
        final String status;
        final String error;
        final boolean typesChanged;

        ParseOutcome(String status, String error, boolean typesChanged) {
            this.status = status;
            this.error = error;
            this.typesChanged = typesChanged;
        }

        boolean ok() { return "ok".equals(status); }
        boolean failed() { return "failed".equals(status); }
        boolean requested() { return !"not_requested".equals(status); }

        Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", status);
            out.put("error", error);
            out.put("types_changed", typesChanged);
            return out;
        }
    }

    static final class PlanRow {
        String portOperationId;
        int index;
        String targetAddr;
        String entry;
        String functionName;
        String requestedName;
        String currentName;
        String nameSource;
        String requestedSignature;
        String currentSignature;
        String signatureSource;
        ParseOutcome parse = parseNotRequested();
        String annotationConflicts;
        boolean previewAnnotations;
        boolean annotationChanged;
        Intent nameIntent = Intent.SKIP;
        Intent signatureIntent = Intent.SKIP;
        Intent annotationIntent = Intent.SKIP;
        Outcome nameOutcome = Outcome.SKIPPED;
        Outcome signatureOutcome = Outcome.SKIPPED;
        Outcome annotationOutcome = Outcome.SKIPPED;
        String status = "skipped";
        String error;

        boolean failed() { return error != null || nameIntent == Intent.FAIL || signatureIntent == Intent.FAIL
            || annotationIntent == Intent.FAIL || (parse != null && parse.failed()); }

        boolean hadApplyIntent() {
            return nameIntent == Intent.APPLY || signatureIntent == Intent.APPLY || annotationIntent == Intent.APPLY;
        }

        Map<String, Object> toMap() {
            Map<String, Object> intended = new LinkedHashMap<>();
            intended.put("name", name(nameIntent));
            intended.put("signature", name(signatureIntent));
            intended.put("annotations", name(annotationIntent));
            Map<String, Object> outcomes = new LinkedHashMap<>();
            outcomes.put("name", name(nameOutcome));
            outcomes.put("signature", name(signatureOutcome));
            outcomes.put("annotations", name(annotationOutcome));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("index", index);
            out.put("target_addr", targetAddr);
            out.put("entry", entry);
            out.put("function", functionName);
            out.put("requested_name", requestedName);
            out.put("current_name", currentName);
            out.put("name_source", nameSource);
            out.put("requested_signature", requestedSignature);
            out.put("current_signature", currentSignature);
            out.put("signature_source", signatureSource);
            out.put("prototype_parse", parse == null ? parseNotRequested().toMap() : parse.toMap());
            out.put("annotation_conflicts", annotationConflicts);
            out.put("intended", intended);
            out.put("outcomes", outcomes);
            out.put("status", status);
            out.put("error", error);
            if (portOperationId != null) out.put("port_ledger", Map.of("operation_id", portOperationId,
                "state", switch (status) { case "committed" -> "applied_unverified"; case "would_commit" -> "would_record"; case "rolled_back" -> "rolled_back"; default -> "unchanged"; }));
            return out;
        }
    }
}
