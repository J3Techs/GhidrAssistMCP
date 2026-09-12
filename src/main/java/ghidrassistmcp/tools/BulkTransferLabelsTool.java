/*
 * MCP tool that bulk-transfers function names and prototypes to a target program.
 */
package ghidrassistmcp.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.ProgramIdentity;
import ghidrassistmcp.tools.TransferPlanSupport.FieldPolicy;
import ghidrassistmcp.tools.TransferPlanSupport.Intent;
import ghidrassistmcp.tools.TransferPlanSupport.PlanRow;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Bulk-transfers function names and optionally prototypes from match results
 * to a target program. Accepts a JSON array of match entries, each with
 * target_addr, name, and optional prototype.
 *
 * <p>COMPATIBILITY: {@code name_policy} and {@code signature_policy} default to
 * {@code default_only}. USER_DEFINED/IMPORTED/ANALYSIS names and signatures are
 * preserved unless {@code replace} is requested. DEFAULT-origin values are
 * updated. Previously this tool always overwrote names.
 *
 * <p>{@code dry_run} validates the whole operation, including isolated prototype
 * parse, and reports per-field outcomes without mutation.
 * {@code preview_annotations} controls only optional annotations.
 */
public class BulkTransferLabelsTool implements McpTool {
    @Override public boolean isLongRunning() { return true; }
    @Override public boolean isReadOnly(Map<String,Object> args) { return Boolean.TRUE.equals(args.get("dry_run")); }

    @Override
    public String getName() {
        return "bulk_transfer_labels";
    }

    @Override
    public String getDescription() {
        return "Bulk-apply function names and prototypes to a target program. " +
               "Requires exact target_program. dry_run validates the whole plan (targets and C prototypes) " +
               "without mutation; preview_annotations controls only optional comments/bookmarks/data_types/" +
               "register_context. name_policy and signature_policy default to default_only: DEFAULT-origin " +
               "values are updated and USER_DEFINED/IMPORTED/ANALYSIS analyst values are preserved unless " +
               "replace is requested (COMPATIBILITY CHANGE from always-overwrite names). " +
               "preview_token is a SHA-256 fingerprint of the validated plan; a stale token fails before " +
               "mutation. Omitting preview_token still fully validates then applies. " +
               "Input: JSON array as 'transfers', each with 'target_addr', 'name', and optional 'prototype'.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public Map<String, Object> getOutputSchema() {
        return TransferPlanSupport.outputSchema();
    }

    @SuppressWarnings("unchecked")
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "transfers", Map.of(
                    "type", "array",
                    "maxItems", TransferPlanSupport.MAX_TRANSFERS,
                    "description", "Array of at most " + TransferPlanSupport.MAX_TRANSFERS + " transfers: [{\"target_addr\": \"0x...\", \"name\": \"funcName\", \"prototype\": \"optional C sig\"}]",
                    "items", Map.of(
                        "type", "object",
                        "properties", Map.of(
                            "target_addr", Map.of("type", "string", "description", "Address in target program"),
                            "name", Map.of("type", "string", "description", "Function name to apply"),
                            "prototype", Map.of("type", "string", "description", "Optional: C function prototype/signature"),
                            "port_metadata", Map.of("type", "object", "description", "Optional bounded PORT provenance with operation_id, source_program_id, source_address, source_fingerprint and method"),
                            "comment", Map.of("type", "string", "description", "Optional plate comment at function entry"),
                            "bookmarks", Map.of("type", "array", "description", "Optional bookmarks [{type,category,comment}]", "items", Map.of("type", "object")),
                            "data_types", Map.of("type", "array", "description", "Optional typed data [{address,data_type,array_count}]", "items", Map.of("type", "object")),
                            "register_context", Map.of("type", "array", "description", "Optional context [{register,value,start,end}]", "items", Map.of("type", "object"))
                        ),
                        "required", List.of("target_addr", "name")
                    )
                ),
                "target_program", Map.of("type", "string", "description", "Exact target program name, project path, URL or program_id; ambiguous names fail"),
                "dry_run", Map.of("type", "boolean", "description", "If true, validate the whole plan without applying changes (default false). Parses prototypes in isolated staging and reports per-field outcomes.", "default", false),
                "conflict_policy", Map.of("type", "string", "enum", List.of("preserve", "replace", "error"), "default", "preserve", "description", "Policy for opt-in annotation conflicts"),
                "preview_annotations", Map.of("type", "boolean", "description", "Preview opt-in annotations without applying (default true when annotations are present). Does not replace dry_run.", "default", true),
                "name_policy", Map.of("type", "string", "enum", List.of("default_only", "replace"), "default", "default_only", "description", "COMPATIBILITY: default_only updates DEFAULT-origin names and preserves USER_DEFINED/IMPORTED/ANALYSIS; replace overwrites"),
                "signature_policy", Map.of("type", "string", "enum", List.of("default_only", "replace"), "default", "default_only", "description", "default_only updates DEFAULT-origin signatures and preserves analyst signatures; replace overwrites"),
                "preview_token", Map.of("type", "string", "description", "Optional SHA-256 fingerprint from a previous dry_run of the same operations, target identity, modification number and policies. Stale tokens fail before mutation. Omit for direct apply after immediate validation.")
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
        return executeWithMonitor(arguments, currentProgram, backend, new ghidra.util.task.TaskMonitorAdapter(true));
    }

    @Override public McpSchema.CallToolResult execute(Map<String,Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, ghidrassistmcp.tasks.McpTask task) {
        return executeWithMonitor(arguments, currentProgram, backend, task == null ? new ghidra.util.task.TaskMonitorAdapter(true)
            : new ghidrassistmcp.tasks.McpTaskMonitor(task, 0, 100, "Transfer annotations"));
    }

    private McpSchema.CallToolResult executeWithMonitor(Map<String,Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, TaskMonitor monitor) {
        String requestedTarget;
        boolean dryRun;
        String conflictPolicy;
        String suppliedToken;
        FieldPolicy namePolicy;
        FieldPolicy signaturePolicy;
        Boolean requestedPreview;
        try {
            requestedTarget = TransferPlanSupport.optionalStringArg(arguments, "target_program");
            dryRun = TransferPlanSupport.booleanArg(arguments, "dry_run", false);
            String conflictRaw = TransferPlanSupport.optionalStringArg(arguments, "conflict_policy");
            conflictPolicy = conflictRaw == null ? "preserve" : conflictRaw;
            AnnotationTransferSupport.parsePolicy(conflictPolicy);
            namePolicy = TransferPlanSupport.fieldPolicyArg(arguments, "name_policy");
            signaturePolicy = TransferPlanSupport.fieldPolicyArg(arguments, "signature_policy");
            suppliedToken = TransferPlanSupport.optionalStringArg(arguments, "preview_token");
            if (arguments.containsKey("preview_annotations") && arguments.get("preview_annotations") != null
                    && !(arguments.get("preview_annotations") instanceof Boolean)) {
                throw new IllegalArgumentException("preview_annotations must be a boolean");
            }
            requestedPreview = arguments.get("preview_annotations") instanceof Boolean b ? b : null;
        } catch (IllegalArgumentException e) {
            return McpSchema.CallToolResult.builder().isError(true).addTextContent(e.getMessage()).build();
        }

        try (var targetLease = ProgramSelection.lease(backend, requestedTarget, currentProgram)) {
            Program targetProgram = targetLease.program();
            Object transfersObj = arguments.get("transfers");
            if (!(transfersObj instanceof List)) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("'transfers' must be a JSON array")
                    .build();
            }

            List<?> rawTransfers = (List<?>) transfersObj;
            if (rawTransfers.size() > TransferPlanSupport.MAX_TRANSFERS) {
                return McpSchema.CallToolResult.builder().isError(true)
                    .addTextContent("transfers exceeds " + TransferPlanSupport.MAX_TRANSFERS + " rows").build();
            }
            List<Map<String, Object>> transfers = new ArrayList<>();
            boolean hasAnnotations = false;
            boolean anyPrototype = false;
            for (int i = 0; i < rawTransfers.size(); i++) {
                Object raw = rawTransfers.get(i);
                if (!(raw instanceof Map<?, ?>)) {
                    return McpSchema.CallToolResult.builder().isError(true)
                        .addTextContent("Transfer #" + (i + 1) + " must be an object").build();
                }
                Map<String, Object> row = (Map<String, Object>) raw;
                if (row.containsKey("port_metadata")) {
                    if (!(row.get("port_metadata") instanceof Map<?, ?> metadata))
                        return ProjectToolSupport.error("Transfer #" + (i + 1) + " port_metadata must be an object");
                    try { PortLedger.validateMetadata((Map<String,Object>) metadata); }
                    catch (IllegalArgumentException e) { return ProjectToolSupport.error("Transfer #" + (i + 1) + ": " + e.getMessage()); }
                }
                transfers.add(row);
                hasAnnotations |= row.containsKey("comment") || row.containsKey("bookmarks")
                    || row.containsKey("data_types") || row.containsKey("register_context");
                anyPrototype |= row.get("prototype") instanceof String proto && !proto.isBlank();
            }
            boolean previewAnnotations = AnnotationTransferSupport.previewByDefault(hasAnnotations, requestedPreview, dryRun);
            boolean applyAnnotations = !dryRun && !previewAnnotations;
            // Token binds to the caller's annotation policy, not the dry_run forced preview.
            boolean annotationPreviewPolicy = requestedPreview == null || requestedPreview;

            String programId = ProgramIdentity.id(targetProgram);
            String programInstance = Integer.toUnsignedString(System.identityHashCode(targetProgram));
            long modificationNumber = targetProgram.getModificationNumber();

            List<PlanRow> rows = new ArrayList<>();
            try (TransferPlanSupport.StagingSnapshot staging = anyPrototype
                    ? TransferPlanSupport.openStaging(targetProgram.getDataTypeManager(), monitor)
                    : null) {
                for (int i = 0; i < transfers.size(); i++) {
                    if (monitor.isCancelled() || Thread.currentThread().isInterrupted()) return ProjectToolSupport.error("Transfer cancelled before mutation");
                    rows.add(planRow(targetProgram, i, transfers.get(i), namePolicy, signaturePolicy,
                        conflictPolicy, annotationPreviewPolicy, staging));
                }
            }

            String previewToken = TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
                programId, programInstance, modificationNumber, namePolicy, signaturePolicy,
                conflictPolicy, annotationPreviewPolicy, transfers));

            if (!TransferPlanSupport.tokenMatches(suppliedToken, previewToken)) {
                TransferPlanSupport.abortBeforeMutation(rows);
                Map<String, Object> stale = TransferPlanSupport.payload(requestedTarget, dryRun, programId,
                    programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                    annotationPreviewPolicy, previewToken, rows,
                    "Stale preview_token; re-preview the current target plan", "none");
                return TransferPlanSupport.result(stale, true);
            }

            if (dryRun) {
                TransferPlanSupport.assignDryRunOutcomes(rows);
                return TransferPlanSupport.result(TransferPlanSupport.payload(requestedTarget, true, programId,
                    programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                    annotationPreviewPolicy, previewToken, rows, null, "none"), false);
            }

            if (TransferPlanSupport.anyPlanFailure(rows)) {
                TransferPlanSupport.abortBeforeMutation(rows);
                return TransferPlanSupport.result(TransferPlanSupport.payload(requestedTarget, false, programId,
                    programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                    annotationPreviewPolicy, previewToken, rows,
                    "Apply aborted before mutation because one or more rows failed validation", "none"), true);
            }

            boolean willMutate = TransferPlanSupport.anyApplyIntent(rows);
            if (willMutate) {
                if (targetProgram.getCurrentTransactionInfo() != null) {
                    return TransferPlanSupport.result(TransferPlanSupport.payload(requestedTarget, false, programId,
                        programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                        annotationPreviewPolicy, previewToken, rows,
                        "Target program has an incompatible enclosing transaction", "none"), true);
                }
                if (!targetProgram.isChangeable()) {
                    return TransferPlanSupport.result(TransferPlanSupport.payload(requestedTarget, false, programId,
                        programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                        annotationPreviewPolicy, previewToken, rows,
                        "Target program is not writable", "none"), true);
                }
            } else {
                TransferPlanSupport.assignApplyOutcomes(rows);
                return TransferPlanSupport.result(TransferPlanSupport.payload(requestedTarget, false, programId,
                    programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                    annotationPreviewPolicy, previewToken, rows, null, "none"), false);
            }

            if (targetProgram.getModificationNumber() != modificationNumber) {
                TransferPlanSupport.abortBeforeMutation(rows);
                Map<String, Object> staleRev = TransferPlanSupport.payload(requestedTarget, false, programId,
                    programInstance, targetProgram.getModificationNumber(), namePolicy, signaturePolicy,
                    conflictPolicy, annotationPreviewPolicy, previewToken, rows,
                    "Target revision changed before apply; re-preview the current plan", "none");
                return TransferPlanSupport.result(staleRev, true);
            }
            if (targetProgram.getCurrentTransactionInfo() != null) {
                TransferPlanSupport.abortBeforeMutation(rows);
                return TransferPlanSupport.result(TransferPlanSupport.payload(requestedTarget, false, programId,
                    programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                    annotationPreviewPolicy, previewToken, rows,
                    "Target program has an incompatible enclosing transaction", "none"), true);
            }

            String txDescription = "MCP bulk_transfer_labels " + Long.toUnsignedString(System.nanoTime());
            String operationId = txDescription;
            int txId = targetProgram.startTransaction(txDescription);
            boolean commit = false;
            try {
                int currentIndex = 0;
                try {
                    // Check transaction ownership before rejecting a changed revision: a
                    // racing GUI writer may own the enclosing transaction and its edits.
                    var tx = targetProgram.getCurrentTransactionInfo();
                    if (tx != null && tx.getOpenSubTransactions().stream().anyMatch(description ->
                            !TransferPlanSupport.ownTransactionDescription(description, txDescription))) {
                        commit = true;
                        TransferPlanSupport.abortBeforeMutation(rows);
                        return TransferPlanSupport.result(TransferPlanSupport.payload(requestedTarget, false, programId,
                            programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                            annotationPreviewPolicy, previewToken, rows,
                            "Another writer started a transaction; no labels applied", "none"), true);
                    }
                    if (targetProgram.getModificationNumber() != modificationNumber) {
                        TransferPlanSupport.abortBeforeMutation(rows);
                        Map<String, Object> staleRev = TransferPlanSupport.payload(requestedTarget, false, programId,
                            programInstance, targetProgram.getModificationNumber(), namePolicy, signaturePolicy,
                            conflictPolicy, annotationPreviewPolicy, previewToken, rows,
                            "Target revision changed before apply; re-preview the current plan", "none");
                        return TransferPlanSupport.result(staleRev, true);
                    }
                    for (; currentIndex < rows.size(); currentIndex++) {
                        monitor.checkCancelled();
                        if (Thread.currentThread().isInterrupted()) throw new IllegalStateException("Transfer interrupted");
                        applyRow(targetProgram, rows.get(currentIndex), transfers.get(currentIndex),
                            conflictPolicy, applyAnnotations, monitor);
                        String ledgerEntry = rows.get(currentIndex).entry != null ? rows.get(currentIndex).entry : rows.get(currentIndex).targetAddr;
                        Address ledgerAddress = targetProgram.getAddressFactory().getAddress(ledgerEntry);
                        Function ledgerFunction = ledgerAddress == null ? null : targetProgram.getFunctionManager().getFunctionAt(ledgerAddress);
                        Object metadata = transfers.get(currentIndex).get("port_metadata");
                        if (ledgerFunction != null && rows.get(currentIndex).hadApplyIntent() && metadata instanceof Map<?, ?> rawMetadata) {
                            @SuppressWarnings("unchecked") Map<String,Object> ledgerMetadata = (Map<String,Object>) rawMetadata;
                            PortLedger.appliedUnverified(targetProgram, ledgerFunction, operationId, ledgerMetadata);
                        }
                    }
                    TransferPlanSupport.assignApplyOutcomes(rows);
                    Map<String, Object> success = TransferPlanSupport.payload(requestedTarget, false, programId,
                        programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                        annotationPreviewPolicy, previewToken, rows, null, "committed");
                    String json = TransferPlanSupport.toJson(success);
                    monitor.checkCancelled();
                    if (Thread.currentThread().isInterrupted()) throw new IllegalStateException("Transfer interrupted before commit");
                    commit = true;
                    return TransferPlanSupport.callResult(success, json, false);
                } catch (Exception e) {
                    String applyError = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                    if (currentIndex < rows.size()) rows.get(currentIndex).error = applyError;
                    TransferPlanSupport.markWholeCallRollback(rows, currentIndex, applyError);
                    Map<String, Object> rolled = TransferPlanSupport.payload(requestedTarget, false, programId,
                        programInstance, modificationNumber, namePolicy, signaturePolicy, conflictPolicy,
                        annotationPreviewPolicy, previewToken, rows,
                        "Transaction failed; all changes rolled back: " + applyError, "rolled_back");
                    return TransferPlanSupport.result(rolled, true);
                }
            } finally {
                targetProgram.endTransaction(txId, commit);
            }
        } catch (IllegalArgumentException e) {
            return ProjectToolSupport.error(e.getMessage());
        }
    }

    private PlanRow planRow(Program program, int index, Map<String, Object> entry,
            FieldPolicy namePolicy, FieldPolicy signaturePolicy, String conflictPolicy,
            boolean previewAnnotations, TransferPlanSupport.StagingSnapshot staging) {
        PlanRow row = new PlanRow();
        row.index = index;
        row.previewAnnotations = previewAnnotations;
        Object addrObj = entry.get("target_addr");
        Object nameObj = entry.get("name");
        if (addrObj != null && !(addrObj instanceof String)) {
            row.error = "target_addr must be a string";
            row.nameIntent = Intent.FAIL;
            row.status = "failed";
            return row;
        }
        if (nameObj != null && !(nameObj instanceof String)) {
            row.error = "name must be a string";
            row.nameIntent = Intent.FAIL;
            row.status = "failed";
            return row;
        }
        if (entry.containsKey("prototype") && entry.get("prototype") != null && !(entry.get("prototype") instanceof String)) {
            row.error = "prototype must be a string";
            row.signatureIntent = Intent.FAIL;
            row.status = "failed";
            return row;
        }
        row.targetAddr = addrObj instanceof String s ? s : null;
        row.requestedName = nameObj instanceof String s ? s : null;
        row.requestedSignature = entry.get("prototype") instanceof String proto ? proto : null;

        if (row.targetAddr == null || row.targetAddr.isBlank() || row.requestedName == null || row.requestedName.isBlank()) {
            row.error = "missing target_addr or name";
            row.nameIntent = Intent.FAIL;
            row.status = "failed";
            return row;
        }

        Address addr = program.getAddressFactory().getAddress(row.targetAddr);
        if (addr == null) {
            row.error = "invalid address " + row.targetAddr;
            row.nameIntent = Intent.FAIL;
            row.status = "failed";
            return row;
        }
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) func = program.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            row.error = "no function at " + row.targetAddr + " (" + row.requestedName + ")";
            row.entry = addr.toString();
            row.nameIntent = Intent.FAIL;
            row.status = "failed";
            return row;
        }

        row.entry = func.getEntryPoint().toString();
        row.functionName = func.getName();
        row.currentName = func.getName();
        row.nameSource = func.getSymbol().getSource().toString();
        row.currentSignature = func.getPrototypeString(false, false);
        row.signatureSource = func.getSignatureSource().toString();
        if (entry.containsKey("port_metadata")) {
            try { PortLedger.fingerprint(func); }
            catch (IllegalArgumentException e) { row.error = e.getMessage(); row.annotationIntent = Intent.FAIL; return row; }
            row.portOperationId = (String)((Map<?,?>)entry.get("port_metadata")).get("operation_id");
        }

        boolean sigRequested = row.requestedSignature != null && !row.requestedSignature.isBlank();
        if (sigRequested) {
            row.parse = staging == null
                ? TransferPlanSupport.parseFailure("prototype requested without a staging snapshot")
                : TransferPlanSupport.parsePrototypeIsolated(staging, row.requestedSignature);
            if (row.parse.failed()) {
                row.signatureIntent = Intent.FAIL;
                row.error = "prototype parse failed: " + row.parse.error;
            } else {
                row.signatureIntent = TransferPlanSupport.decideField(true, row.requestedSignature,
                    row.currentSignature, row.signatureSource, signaturePolicy);
            }
        } else {
            row.parse = TransferPlanSupport.parseNotRequested();
            row.signatureIntent = Intent.SKIP;
        }

        row.nameIntent = TransferPlanSupport.decideField(true, row.requestedName, row.currentName,
            row.nameSource, namePolicy);

        AnnotationResult annotation = validateOrApplyAnnotations(program, func, entry, conflictPolicy, false);
        row.annotationChanged = annotation.changed;
        if (annotation.error != null) {
            row.annotationIntent = Intent.FAIL;
            row.annotationConflicts = annotation.error;
            row.error = annotation.error;
        } else if (!previewAnnotations && annotation.changed) {
            row.annotationIntent = Intent.APPLY;
        } else if (annotation.conflict) {
            row.annotationIntent = Intent.PRESERVE;
            row.annotationConflicts = annotation.error;
        } else {
            row.annotationIntent = Intent.SKIP;
        }

        if (row.failed()) row.status = "failed";
        else row.status = TransferPlanSupport.rowStatus(row);
        return row;
    }

    private void applyRow(Program program, PlanRow row, Map<String, Object> entry,
            String conflictPolicy, boolean applyAnnotations, TaskMonitor monitor) throws Exception {
        Address addr = program.getAddressFactory().getAddress(row.entry != null ? row.entry : row.targetAddr);
        Function func = addr == null ? null : program.getFunctionManager().getFunctionAt(addr);
        if (func == null && addr != null) func = program.getFunctionManager().getFunctionContaining(addr);
        if (func == null) throw new IllegalStateException(row.error != null ? row.error : "no function at " + row.targetAddr);

        if (row.nameIntent == Intent.APPLY) {
            func.setName(row.requestedName, SourceType.IMPORTED);
        }
        if (row.signatureIntent == Intent.APPLY) {
            applyPrototype(program, func, row.requestedSignature, monitor);
        }
        if (applyAnnotations && row.annotationIntent == Intent.APPLY) {
            AnnotationResult annotation = validateOrApplyAnnotations(program, func, entry, conflictPolicy, true);
            if (annotation.error != null) throw new IllegalStateException(annotation.error);
        }
    }

    private void applyPrototype(Program program, Function func, String prototype, TaskMonitor monitor) throws Exception {
        FunctionSignatureParser parser = new FunctionSignatureParser(program.getDataTypeManager(), null);
        FunctionDefinitionDataType sig = parser.parse(null, prototype);
        if (sig == null) throw new IllegalStateException("Failed to parse function prototype: " + prototype);
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
            func.getEntryPoint(), sig, SourceType.IMPORTED, false, false,
            DataTypeConflictHandler.DEFAULT_HANDLER, FunctionRenameOption.NO_CHANGE);
        boolean ok = cmd.applyTo(program, monitor);
        if (TransferPlanSupport.nativeCommandFailed(ok, cmd.getStatusMsg())) {
            throw new IllegalStateException(TransferPlanSupport.nativeCommandMessage(ok, cmd.getStatusMsg()));
        }
    }

    @SuppressWarnings("unchecked")
    private AnnotationResult validateOrApplyAnnotations(Program p, Function f, Map<String, Object> e,
                                                         String policy, boolean apply) {
        try {
            boolean changed = false;
            boolean conflict = false;
            String comment = e.get("comment") instanceof String ? (String) e.get("comment") : null;
            if (comment != null) {
                String old = f.getComment();
                if (old != null && !old.equals(comment)) {
                    if ("error".equals(policy)) return new AnnotationResult(false, true, "comment conflict at " + f.getEntryPoint());
                    if ("replace".equals(policy) && apply) f.setComment(comment);
                    changed = "replace".equals(policy);
                    conflict = !"replace".equals(policy);
                } else if (old == null) {
                    if (apply) f.setComment(comment);
                    changed = true;
                }
            }
            Object bm = e.get("bookmarks");
            if (bm != null && !(bm instanceof List)) return new AnnotationResult(false, false, "bookmarks must be an array");
            if (bm instanceof List) for (Object raw : (List<?>) bm) {
                if (!(raw instanceof Map<?, ?>)) return new AnnotationResult(false, false, "bookmark entry must be an object");
                Map<String, Object> b = (Map<String, Object>) raw;
                String type = b.get("type") instanceof String ? (String) b.get("type") : BookmarkType.NOTE;
                String category = b.get("category") instanceof String ? (String) b.get("category") : "Analysis";
                String text = b.get("comment") instanceof String ? (String) b.get("comment") : "MCP annotation";
                var existing = p.getBookmarkManager().getBookmark(f.getEntryPoint(), type, category);
                if (existing != null && !existing.getComment().equals(text)) {
                    if ("error".equals(policy)) return new AnnotationResult(false, true, "bookmark conflict at " + f.getEntryPoint());
                    if ("preserve".equals(policy)) { conflict = true; continue; }
                    if (apply) p.getBookmarkManager().removeBookmark(existing);
                }
                if (apply) p.getBookmarkManager().setBookmark(f.getEntryPoint(), type, category, text);
                changed = true;
            }
            Object dts = e.get("data_types");
            if (dts != null && !(dts instanceof List)) return new AnnotationResult(false, false, "data_types must be an array");
            if (dts instanceof List) for (Object raw : (List<?>) dts) {
                if (!(raw instanceof Map<?, ?>)) return new AnnotationResult(false, false, "data_types entry must be an object");
                Map<String, Object> d = (Map<String, Object>) raw;
                String as = d.get("address") instanceof String ? (String) d.get("address") : f.getEntryPoint().toString();
                String tn = d.get("data_type") instanceof String ? (String) d.get("data_type") : null;
                if (tn == null) return new AnnotationResult(false, false, "data_types entry missing data_type");
                DataTypeResolver.Result resolved = DataTypeResolver.resolve(p.getDataTypeManager(), tn, d.get("array_count"));
                if (resolved.isError()) return new AnnotationResult(false, false, resolved.errorMessage);
                Address a = p.getAddressFactory().getAddress(as);
                if (a == null) return new AnnotationResult(false, false, "invalid data_types address " + as);
                DataType dt = resolved.dataType;
                if (dt.getLength() < 1 || dt.getLength() > 1048576)
                    return new AnnotationResult(false, false, "data type must have a fixed length of 1..1048576 bytes");
                Address last = a.addNoWrap(dt.getLength() - 1);
                if (!p.getMemory().contains(a, last)) return new AnnotationResult(false, false, "data type range is not mapped memory");
                var span = new ghidra.program.model.address.AddressSet(a, last);
                var existing = p.getListing().getDefinedDataAt(a);
                boolean same = existing != null && existing.getLength() == dt.getLength() && existing.getDataType().isEquivalent(dt);
                if (same) continue;
                boolean occupied = p.getListing().getDefinedDataContaining(a) != null
                    || p.getListing().getInstructionContaining(a) != null
                    || p.getListing().getDefinedData(span, true).hasNext()
                    || p.getListing().getInstructions(span, true).hasNext();
                if (occupied) {
                    if ("error".equals(policy)) return new AnnotationResult(false, true, "data type conflict at " + a);
                    if ("preserve".equals(policy)) { conflict = true; continue; }
                }
                if (apply) {
                    if (occupied) p.getListing().clearCodeUnits(a, last, false);
                    p.getListing().createData(a, dt);
                }
                changed = true;
            }
            Object rc = e.get("register_context");
            if (rc != null && !(rc instanceof List)) return new AnnotationResult(false, false, "register_context must be an array");
            if (rc instanceof List) for (Object raw : (List<?>) rc) {
                if (!(raw instanceof Map<?, ?>)) return new AnnotationResult(false, false, "register_context entry must be an object");
                Map<String, Object> c = (Map<String, Object>) raw;
                String rn = c.get("register") instanceof String ? (String) c.get("register") : null;
                String vs = c.get("value") instanceof String ? (String) c.get("value") : String.valueOf(c.get("value"));
                String ss = c.get("start") instanceof String ? (String) c.get("start") : f.getEntryPoint().toString();
                String es = c.get("end") instanceof String ? (String) c.get("end") : f.getBody().getMaxAddress().toString();
                Register r = p.getProgramContext().getRegister(rn);
                Address s = p.getAddressFactory().getAddress(ss), end = p.getAddressFactory().getAddress(es);
                if (r == null || s == null || end == null || s.compareTo(end) > 0 || c.get("value") == null)
                    return new AnnotationResult(false, false, "invalid register_context entry");
                BigInteger requested;
                try { requested = new BigInteger(vs.replaceFirst("(?i)^0x", ""), vs.toLowerCase().startsWith("0x") ? 16 : 10); }
                catch (NumberFormatException ex) { return new AnnotationResult(false, false, "invalid register_context value"); }
                if (!s.getAddressSpace().equals(end.getAddressSpace()) || requested.signum() < 0 || requested.bitLength() > r.getBitLength())
                    return new AnnotationResult(false, false, "register context range/value exceeds register bounds");
                var context = p.getProgramContext();
                var intervals = context.getRegisterValueAddressRanges(r, s, end);
                boolean intervalConflict = false;
                int checked = 0;
                while (intervals.hasNext()) {
                    if (++checked > 10000) return new AnnotationResult(false, false, "register context exceeds 10000 segments");
                    var interval = intervals.next();
                    BigInteger existing = context.getValue(r, interval.getMinAddress(), false);
                    intervalConflict |= existing != null && !existing.equals(requested);
                }
                if (intervalConflict) {
                    if ("error".equals(policy)) return new AnnotationResult(false, true, "register context conflict at " + s);
                    if ("preserve".equals(policy)) { conflict = true; continue; }
                }
                if (apply) p.getProgramContext().setValue(r, s, end, requested);
                changed = true;
            }
            return new AnnotationResult(changed, conflict, null);
        } catch (Exception ex) {
            return new AnnotationResult(false, false, ex.getMessage());
        }
    }

    private static final class AnnotationResult {
        final boolean changed;
        final boolean conflict;
        final String error;
        AnnotationResult(boolean changed, boolean conflict, String error) {
            this.changed = changed;
            this.conflict = conflict;
            this.error = error;
        }
    }
}
