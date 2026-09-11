package ghidrassistmcp.bsim;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.FunctionUtility;
import ghidra.util.task.TaskMonitor;

/** Preview and explicitly confirmed application of BSim match metadata. */
public final class BsimMatchOperations {
    private static final int MAX_TARGETS = 500;

    private BsimMatchOperations() {
    }

    public static List<BsimOperation> operations() {
        return List.of(
            BsimOperation.of("preview_matches", "Preview selected BSim match metadata without modifying programs.",
                Map.of("matches", matchArray(), "limit", field("integer", 1, MAX_TARGETS)),
                List.of("matches"), true, false, false, BsimMatchOperations::previewMatches),
            BsimOperation.of("apply_matches", "Apply explicitly selected match names with per-target rollback.",
                Map.of("preview_id", field("string", null, null), "selected", indexArray(),
                    "confirm", field("boolean", null, null)),
                List.of("preview_id", "selected", "confirm"), false, true, false, BsimMatchOperations::applyMatches));
    }

    private static Map<String, Object> field(String type, Number minimum, Number maximum) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", type);
        if (minimum != null) value.put("minimum", minimum);
        if (maximum != null) value.put("maximum", maximum);
        return value;
    }

    private static Map<String, Object> matchArray() {
        Map<String, Object> value = field("array", null, null);
        value.put("items", Map.of("type", "object", "properties", Map.ofEntries(
            Map.entry("program", field("string", null, null)), Map.entry("address", field("string", null, null)),
            Map.entry("name", field("string", null, null)), Map.entry("prototype", field("string", null, null)), Map.entry("comment", field("string", null, null)),
            Map.entry("source_program", field("string", null, null)), Map.entry("source_address", field("string", null, null)),
            Map.entry("overwrite", field("boolean", null, null)), Map.entry("transfer_name", field("boolean", null, null)),
            Map.entry("transfer_signature", field("boolean", null, null)), Map.entry("transfer_comments", field("boolean", null, null))),
            "required", List.of("program", "address")));
        return value;
    }

    private static Map<String, Object> indexArray() {
        Map<String, Object> value = field("array", null, null);
        value.put("items", field("integer", 0, MAX_TARGETS - 1));
        return value;
    }

    private static Map<String, Object> previewMatches(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        List<Map<String, Object>> requested = matchMaps(args);
        List<Map<String, Object>> rows = new ArrayList<>();
        int limit = BsimSupport.integer(args, "limit", requested.size(), MAX_TARGETS);
        for (int i = 0; i < requested.size() && rows.size() < limit; i++) {
            monitor.checkCancelled();
            Map<String, Object> match = requested.get(i);
            Map<String, Object> row = new LinkedHashMap<>(match);
            row.putIfAbsent("transfer_name", true);
            row.putIfAbsent("transfer_signature", false);
            row.putIfAbsent("transfer_comments", false);
            String sourceProgram = match.get("source_program") instanceof String s ? s : null;
            String sourceAddress = match.get("source_address") instanceof String s ? s : null;
            if (sourceProgram != null && sourceAddress != null) populateSourceProposal(context, row, monitor);
            populateTarget(context, row, monitor);
            row.put("afterName", row.getOrDefault("name", row.get("beforeName")));
            row.put("conflict", !String.valueOf(row.get("beforeName")).equals(String.valueOf(row.get("afterName")))
                && !Boolean.TRUE.equals(row.get("overwrite")));
            row.put("programFingerprint", fingerprint(context, row, monitor));
            if (match.get("source_program") instanceof String && match.get("source_address") instanceof String) {
                row.put("sourceFingerprint", sourceFingerprint(context, row, monitor));
            }
            row.put("status", "preview");
            row.put("staleChecked", true);
            row.put("requiresExplicitSelection", true);
            rows.add(row);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("matches", rows);
        result.put("count", rows.size());
        result.put("truncated", rows.size() < requested.size());
        result.put("readOnly", true);
        String previewId = UUID.randomUUID().toString();
        result.put("previewId", previewId);
        BsimSupport.atomicJson(context.artifacts().resolve("bsim-previews").resolve(previewId + ".json"), result);
        return result;
    }

    private static Map<String, Object> applyMatches(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        if (!BsimSupport.bool(args, "confirm", false)) {
            throw new IllegalArgumentException("confirm=true is required to apply selected matches");
        }
        String previewId = BsimSupport.text(args, "preview_id");
        try { UUID.fromString(previewId); } catch (IllegalArgumentException e) { throw new IllegalArgumentException("preview_id must be a UUID"); }
        Object selectedValue = args.get("selected");
        if (!(selectedValue instanceof List<?> selected)) throw new IllegalArgumentException("selected must be an array");
        Path artifactRoot = context.artifacts().toAbsolutePath().normalize();
        Path previewPath = artifactRoot.resolve("bsim-previews").resolve(previewId + ".json").normalize();
        if (!previewPath.startsWith(artifactRoot)) throw new IllegalArgumentException("invalid preview id");
        Map<String, Object> preview = BsimSupport.readJson(previewPath);
        Object previewMatches = preview.get("matches");
        if (!(previewMatches instanceof List<?> all)) throw new IllegalArgumentException("preview is malformed");
        List<Map<String, Object>> requested = new ArrayList<>();
        java.util.Set<Integer> selectedPositions = new java.util.HashSet<>();
        for (Object index : selected) {
            if (!(index instanceof Number number)) throw new IllegalArgumentException("selected entries must be indices");
            int position;
            try { position = new java.math.BigDecimal(number.toString()).intValueExact(); }
            catch (ArithmeticException e) { throw new IllegalArgumentException("selected indices must be exact integers"); }
            if (!selectedPositions.add(position)) throw new IllegalArgumentException("selected contains duplicate indices");
            if (position < 0 || position >= all.size() || !(all.get(position) instanceof Map<?, ?> map))
                throw new IllegalArgumentException("selected index is outside preview");
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) if (entry.getKey() instanceof String key) copy.put(key, entry.getValue());
            requested.add(copy);
        }
        if (requested.size() > MAX_TARGETS) {
            throw new IllegalArgumentException("matches exceeds maximum of " + MAX_TARGETS);
        }
        for (Map<String, Object> match : requested) {
            if (monitor.isCancelled()) throw new IllegalStateException("apply cancelled before mutation");
            String actualTarget = fingerprint(context, match, monitor);
            if (match.get("programFingerprint") instanceof String expected && !expected.equals(actualTarget))
                throw new IllegalStateException("preview is stale for target program");
            if (match.get("sourceFingerprint") instanceof String expectedSource) {
                String actualSource = sourceFingerprint(context, match, monitor);
                if (!expectedSource.equals(actualSource)) throw new IllegalStateException("preview is stale for source program");
            }
        }
        Map<String, List<Map<String, Object>>> groups = new LinkedHashMap<>();
        var targets = new java.util.HashSet<String>();
        for (Map<String, Object> match : requested) {
            String identity = BsimSupport.text(match, "program") + ":" + BsimSupport.text(match, "address");
            if (!targets.add(identity)) throw new IllegalArgumentException("Select only one match per target function");
            groups.computeIfAbsent(BsimSupport.text(match, "program"), k -> new ArrayList<>()).add(match);
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (List<Map<String, Object>> group : groups.values()) {
            if (monitor.isCancelled()) throw new IllegalStateException("apply cancelled before mutation");
            boolean committed = false;
            int transaction = -1;
            boolean found = false;
            try {
                String requestedProgram = BsimSupport.text(group.get(0), "program");
                for (BsimContext.ProgramHandle handle : context.resolvePrograms(Map.of("programs", List.of(requestedProgram)), monitor, true)) {
                    try (handle) {
                        found = true;
                        handle.retainForReview();
                        Program program = handle.program();
                        if (program.getCurrentTransactionInfo() != null) throw new IllegalStateException("Target program has an active transaction");
                        transaction = program.startTransaction("Apply BSim matches");
                        try {
                            for (Map<String, Object> match : group) {
                                monitor.checkCancelled();
                                applyOne(context, match, monitor, false);
                            }
                            committed = true;
                        }
                        finally {
                            program.endTransaction(transaction, committed);
                            transaction = -1;
                        }
                        break;
                    }
                }
                if (!found) throw new IllegalArgumentException("program not found: " + requestedProgram);
            }
            catch (Exception e) {
                for (Map<String, Object> match : group) {
                    Map<String, Object> row = new LinkedHashMap<>(match);
                    row.put("status", "rolled_back"); row.put("error", e.getMessage()); rows.add(row);
                }
            }
            if (committed) for (Map<String, Object> match : group) { Map<String, Object> row = new LinkedHashMap<>(match); row.put("status", "applied"); rows.add(row); }
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("matches", rows);
        result.put("count", rows.size());
        result.put("truncated", rows.size() < requested.size());
        result.put("readOnly", false);
        return result;
    }

    private static String fingerprint(BsimContext context, Map<String, Object> match,
            TaskMonitor monitor) throws Exception {
        String requested = BsimSupport.text(match, "program");
        for (BsimContext.ProgramHandle handle : context.resolvePrograms(Map.of("programs", List.of(requested)), monitor)) {
            try (handle) {
                Program program = handle.program();
                return stamp(handle, program);
            }
        }
        throw new IllegalArgumentException("program not found: " + requested);
    }

    private static String stamp(BsimContext.ProgramHandle handle, Program program) {
        return handle.identity() + "@" + program.getDomainFile().getLastModifiedTime() + ":" + program.getModificationNumber();
    }
    private static void populateTarget(BsimContext context, Map<String, Object> match, TaskMonitor monitor) throws Exception {
        String requested = BsimSupport.text(match, "program");
        for (BsimContext.ProgramHandle handle : context.resolvePrograms(Map.of("programs", List.of(requested)), monitor)) {
            try (handle) {
                Function function = handle.program().getFunctionManager().getFunctionAt(
                    handle.program().getAddressFactory().getAddress(BsimSupport.text(match, "address")));
                if (function == null) throw new IllegalArgumentException("Target function not found");
                match.put("program", handle.identity()); match.put("address", function.getEntryPoint().toString());
                match.put("beforeName", function.getName()); match.put("beforePrototype", function.getSignature().getPrototypeString());
                match.put("beforeComment", function.getComment() == null ? "" : function.getComment());
                match.put("namePreserved", function.getSymbol().getSource() != SourceType.DEFAULT && !BsimSupport.bool(match, "overwrite", false));
                return;
            }
        }
        throw new IllegalArgumentException("program not found: " + requested);
    }

    private static void populateSourceProposal(BsimContext context, Map<String, Object> row, TaskMonitor monitor) throws Exception {
        String requested = BsimSupport.text(row, "source_program");
        for (BsimContext.ProgramHandle handle : context.resolvePrograms(Map.of("programs", List.of(requested)), monitor)) {
            try (handle) {
                Function function = handle.program().getFunctionManager().getFunctionAt(
                    handle.program().getAddressFactory().getAddress(BsimSupport.text(row, "source_address")));
                if (function == null) throw new IllegalArgumentException("source function not found");
                row.putIfAbsent("name", function.getName());
                row.putIfAbsent("prototype", function.getSignature().getPrototypeString());
                if (function.getComment() != null) row.putIfAbsent("comment", function.getComment());
                if (function.getRepeatableComment() != null) row.putIfAbsent("repeatable_comment", function.getRepeatableComment());
                row.put("source_program", handle.identity()); row.put("source_address", function.getEntryPoint().toString());
                row.put("sourceFingerprint", stamp(handle, handle.program()));
                return;
            }
        }
        throw new IllegalArgumentException("source program not found: " + requested);
    }

    private static String sourceFingerprint(BsimContext context, Map<String, Object> match,
            TaskMonitor monitor) throws Exception {
        String requested = BsimSupport.text(match, "source_program");
        for (BsimContext.ProgramHandle handle : context.resolvePrograms(Map.of("programs", List.of(requested)), monitor)) {
            try (handle) {
                return stamp(handle, handle.program());
            }
        }
        throw new IllegalArgumentException("source program not found: " + requested);
    }

    private static void applyOne(BsimContext context, Map<String, Object> match,
            TaskMonitor monitor) throws Exception {
        applyOne(context, match, monitor, true);
    }

    private static void applyOne(BsimContext context, Map<String, Object> match,
            TaskMonitor monitor, boolean ownTransaction) throws Exception {
        String requested = BsimSupport.text(match, "program");
        for (BsimContext.ProgramHandle handle : context.resolvePrograms(Map.of("programs", List.of(requested)), monitor, true)) {
            try (handle) {
                {
                    Program program = handle.program();
                    Address address = program.getAddressFactory().getAddress(
                        BsimSupport.text(match, "address"));
                    Function function = program.getFunctionManager().getFunctionAt(address);
                    if (function == null) throw new IllegalArgumentException("no function at address " + address);
                    String name = match.get("name") instanceof String s ? s : null;
                    int transaction = ownTransaction ? program.startTransaction("Apply BSim match") : -1;
                    boolean commit = false;
                    try {
                        boolean overwrite = BsimSupport.bool(match, "overwrite", false);
                        boolean transferName = BsimSupport.bool(match, "transfer_name", name != null);
                        if (transferName && name != null && name.isBlank()) {
                            throw new IllegalArgumentException("name cannot be blank when transfer_name is enabled");
                        }
                        if (transferName && name != null && (overwrite || function.getSymbol().getSource() == SourceType.DEFAULT)) {
                            function.setName(name, SourceType.USER_DEFINED);
                        }
                        String sourceProgram = match.get("source_program") instanceof String s ? s : null;
                        String sourceAddress = match.get("source_address") instanceof String s ? s : null;
                        boolean transferSignature = BsimSupport.bool(match, "transfer_signature", false);
                        if (transferSignature && (sourceProgram == null || sourceAddress == null)) throw new IllegalArgumentException("Signature transfer requires source_program and source_address");
                        if (transferSignature && (overwrite || function.getSignatureSource() == SourceType.DEFAULT)) {
                            for (BsimContext.ProgramHandle sourceHandle : context.resolvePrograms(
                                    Map.of("programs", List.of(sourceProgram)), monitor)) {
                                try (sourceHandle) {
                                    Address sourceAddr = sourceHandle.program().getAddressFactory().getAddress(sourceAddress);
                                    Function sourceFunction = sourceHandle.program().getFunctionManager().getFunctionAt(sourceAddr);
                                    if (sourceFunction == null) throw new IllegalArgumentException("no source function at " + sourceAddress);
                                    FunctionUtility.applySignature(function, sourceFunction, false, null);
                                    break;
                                }
                            }
                        }
                        Object comment = match.get("comment");
                        boolean transferComments = BsimSupport.bool(match, "transfer_comments", false);
                        if (transferComments && comment instanceof String text && !text.isBlank()
                                && (overwrite || function.getComment() == null)) function.setComment(text);
                        if (transferComments && match.get("repeatable_comment") instanceof String repeatable
                                && (overwrite || function.getRepeatableComment() == null)) function.setRepeatableComment(repeatable);
                        commit = true;
                    }
                    finally {
                        if (ownTransaction) program.endTransaction(transaction, commit);
                    }
                    return;
                }
            }
        }
        throw new IllegalArgumentException("program not found: " + requested);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> matchMaps(Map<String, Object> args) {
        Object value = args.get("matches");
        if (!(value instanceof List<?> list)) {
            throw new IllegalArgumentException("matches must be an array");
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Object item : list) {
            if (!(item instanceof Map<?, ?> map)) throw new IllegalArgumentException("each match must be an object");
            Map<String, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) throw new IllegalArgumentException("match keys must be strings");
                copy.put(key, entry.getValue());
            }
            if (!copy.containsKey("program") || !copy.containsKey("address")) {
                throw new IllegalArgumentException("each match requires program and address");
            }
            result.add(copy);
        }
        return result;
    }
}
