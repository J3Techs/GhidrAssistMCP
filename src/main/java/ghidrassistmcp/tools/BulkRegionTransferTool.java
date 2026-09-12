/*
 * MCP tool for bulk region-based function label transfer between binaries.
 * Transfers all named function labels from a source program to a target program
 * for a given address range, with automatic offset detection and verification.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.ProgramIdentity;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Bulk-transfers all named function labels from a source program to a target program
 * for a given address range. Auto-detects the code offset between binaries, verifies
 * each match via opcode comparison, and optionally creates missing function definitions.
 *
 * Three phases:
 *   A. Offset Detection — samples functions and byte-matches to find the address delta
 *   B. Verified Transfer — applies labels only after size + opcode verification
 *   C. Report — structured output with match/mismatch/skip details
 */
public class BulkRegionTransferTool implements McpTool {
    @Override public boolean isLongRunning() { return true; }
    @Override public boolean isReadOnly(Map<String,Object> args) { return Boolean.TRUE.equals(args.get("dry_run")); }

    private static final int OFFSET_SEARCH_RANGE = 0x8000;
    private static final int OFFSET_SAMPLE_COUNT = 10;
    private static final int OFFSET_MIN_FUNC_SIZE = 40;
    private static final int OFFSET_PATTERN_WORDS = 4; // 4 instruction words = 16 bytes
    private static final int MIN_AGREEING_SAMPLES = 3;
    private static final double OPCODE_MATCH_THRESHOLD = 0.70;
    private static final int VERIFY_MAX_BYTES = 64;
    private static final int CONSECUTIVE_MISMATCH_WARN = 3;

    @Override
    public String getName() {
        return "bulk_region_transfer";
    }

    @Override
    public String getDescription() {
        return "Transfer all named function labels from a source program to a target program " +
               "for a given address range. Auto-detects code offset between binaries, verifies each " +
               "match via size and opcode comparison, and optionally creates missing function definitions. " +
               "Apply is atomic: any failed creation, rename or verification rolls back all changes made by this call.";
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
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "source_program", Map.of("type", "string",
                    "description", "Exact source name, project path, URL or program_id; ambiguous names fail"),
                "target_program", Map.of("type", "string",
                    "description", "Exact target name, project path, URL or program_id; ambiguous names fail"),
                "start_address", Map.of("type", "string",
                    "description", "Start of source address range (hex, e.g. \"0x00287200\")"),
                "end_address", Map.of("type", "string",
                    "description", "End of source address range (hex, e.g. \"0x002890FF\")"),
                "code_offset", Map.of("type", "integer",
                    "description", "Known offset (target = source + offset). If omitted, auto-detected."),
                "dry_run", Map.of("type", "boolean",
                    "description", "If true, report matches without applying labels (default false)",
                    "default", false),
                "preview_token", Map.of("type", "string", "description", "Token returned by a reviewed dry_run; binds source/target identities and revisions"),
                "name_policy", Map.of("type", "string", "enum", List.of("default_only", "replace"), "default", "default_only"),
                "create_functions", Map.of("type", "boolean",
                    "description", "If true, create function definitions at target addresses when missing (default true)",
                    "default", true),
                "size_tolerance", Map.of("type", "number",
                    "description", "Max size ratio difference allowed (0.2 = +/-20%, default 0.2)",
                    "default", 0.2)
            ),
            List.of("source_program", "target_program", "start_address", "end_address"),
            null, null, null);
    }

    @Override
    public Map<String, Object> getOutputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("source_program", Map.of("type", "string"));
        properties.put("target_program", Map.of("type", "string"));
        properties.put("preview_token", Map.of("type", "string"));
        properties.put("dry_run", Map.of("type", "boolean"));
        properties.put("committed", Map.of("type", "boolean"));
        properties.put("matched", Map.of("type", "integer", "minimum", 0));
        properties.put("functions_created", Map.of("type", "integer", "minimum", 0));
        properties.put("labels_rolled_back", Map.of("type", "integer", "minimum", 0));
        properties.put("functions_rolled_back", Map.of("type", "integer", "minimum", 0));
        properties.put("failures", Map.of("type", "array", "items", Map.of("type", "string")));
        properties.put("mismatches", Map.of("type", "array", "items", Map.of("type", "string")));
        properties.put("details", Map.of("type", "array", "items", Map.of("type", "string")));
        properties.put("fatal_error", Map.of("type", "string"));
        properties.put("comparison_mode", Map.of("type", "string"));
        properties.put("comparison_note", Map.of("type", "string"));
        properties.put("source_language", Map.of("type", "string"));
        properties.put("target_language", Map.of("type", "string"));
        return MatcherContracts.objectSchema(properties, List.of(
            "source_program", "target_program", "dry_run", "committed", "matched",
            "functions_created", "labels_rolled_back", "functions_rolled_back",
            "failures", "mismatches", "details", "fatal_error", "comparison_mode"));
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                             GhidrAssistMCPBackend backend) {
        return execute(arguments, currentProgram, backend, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                             GhidrAssistMCPBackend backend, McpTask task) {
        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        // --- Parse arguments ---
        for (String key : List.of("source_program", "target_program", "start_address", "end_address")) {
            if (!(arguments.get(key) instanceof String value) || value.isBlank())
                return ProjectToolSupport.error(key + " must be a nonblank string");
        }
        for (String key : List.of("preview_token", "name_policy"))
            if (arguments.containsKey(key) && !(arguments.get(key) instanceof String))
                return ProjectToolSupport.error(key + " must be a string");
        String sourceProgramName = (String) arguments.get("source_program");
        String targetProgramName = (String) arguments.get("target_program");
        String startAddrStr = (String) arguments.get("start_address");
        String endAddrStr = (String) arguments.get("end_address");
        String previewToken = arguments.get("preview_token") instanceof String s ? s.trim() : null;
        String namePolicy = arguments.get("name_policy") instanceof String s ? s.trim().toLowerCase() : "default_only";
        if (!namePolicy.equals("default_only") && !namePolicy.equals("replace")) return ProjectToolSupport.error("name_policy must be default_only or replace");

        boolean dryRun = false;
        if (arguments.containsKey("dry_run") && !(arguments.get("dry_run") instanceof Boolean))
            return ProjectToolSupport.error("dry_run must be a boolean");
        if (arguments.get("dry_run") instanceof Boolean b) dryRun = b;

        boolean createFunctions = true;
        if (arguments.containsKey("create_functions") && !(arguments.get("create_functions") instanceof Boolean))
            return ProjectToolSupport.error("create_functions must be a boolean");
        if (arguments.get("create_functions") instanceof Boolean b) createFunctions = b;

        double sizeTolerance = 0.2;
        if (arguments.containsKey("size_tolerance") && !(arguments.get("size_tolerance") instanceof Number))
            return ProjectToolSupport.error("size_tolerance must be a number");
        if (arguments.get("size_tolerance") instanceof Number n) sizeTolerance = n.doubleValue();
        if (!Double.isFinite(sizeTolerance) || sizeTolerance < 0 || sizeTolerance >= 1)
            return ProjectToolSupport.error("size_tolerance must be finite and in [0,1)");

        Long codeOffset = null;
        if (arguments.containsKey("code_offset") && !(arguments.get("code_offset") instanceof Number))
            return ProjectToolSupport.error("code_offset must be an integer");
        if (arguments.get("code_offset") instanceof Number n) {
            try { codeOffset = new java.math.BigDecimal(n.toString()).longValueExact(); }
            catch (ArithmeticException | NumberFormatException e) { return ProjectToolSupport.error("code_offset must be an integer"); }
        }

        TaskMonitor monitor = task == null ? TaskMonitor.DUMMY : new McpTaskMonitor(task, 0, 100, "Bulk region transfer");

        // --- Resolve programs ---
        try (var sourceLease = ProgramSelection.lease(backend, sourceProgramName, currentProgram);
             var targetLease = ProgramSelection.lease(backend, targetProgramName, currentProgram)) {
        Program sourceProgram = sourceLease.program(), targetProgram = targetLease.program();

        if (sourceProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Source program not found: " + sourceProgramName)
                .build();
        }
        if (targetProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Target program not found: " + targetProgramName)
                .build();
        }

        // --- Parse address range ---
        Address startAddr = sourceProgram.getAddressFactory().getAddress(startAddrStr);
        Address endAddr = sourceProgram.getAddressFactory().getAddress(endAddrStr);

        if (startAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid start_address: " + startAddrStr)
                .build();
        }
        if (endAddr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid end_address: " + endAddrStr)
                .build();
        }
        if (startAddr.compareTo(endAddr) >= 0) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("start_address must be less than end_address")
                .build();
        }

        MatcherContracts.LanguageFacts sourceFacts = MatcherContracts.fromProgram(sourceProgram)
            .withRangeContext(MatcherContracts.rangeVleContext(sourceProgram, startAddr, endAddr));
        MatcherContracts.LanguageFacts targetFacts = MatcherContracts.fromProgram(targetProgram)
            .withRangeContext(MatcherContracts.rangeVleContext(targetProgram, null, null));
        MatcherContracts.RegionDecision comparison = MatcherContracts.regionCompare(sourceFacts, targetFacts);
        if (!comparison.allowed() || comparison.mode() == MatcherContracts.RegionCompareMode.REJECTED) {
            return ProjectToolSupport.error(comparison.message());
        }
        long sourceRevisionBeforeScan = sourceProgram.getModificationNumber();
        long targetRevisionBeforeScan = targetProgram.getModificationNumber();
        String planToken = planToken(sourceProgram, targetProgram, startAddrStr, endAddrStr, codeOffset, createFunctions, sizeTolerance, namePolicy);
        if (previewToken != null && !previewToken.isBlank() && !previewToken.equalsIgnoreCase(planToken))
            return ProjectToolSupport.error("Stale preview_token; re-run dry_run against the current source and target");

        // ========== PHASE A: Offset Detection ==========
        long detectedOffset;
        int sampleCount;

        if (codeOffset != null) {
            detectedOffset = codeOffset;
            sampleCount = -1; // user-provided
        } else {
            OffsetResult offsetResult = detectOffset(sourceProgram, targetProgram, startAddr, endAddr,
                sourceFacts, targetFacts, monitor);
            if (offsetResult.error != null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Offset detection failed: " + offsetResult.error)
                    .build();
            }
            if (sourceProgram.getModificationNumber() != sourceRevisionBeforeScan
                    || targetProgram.getModificationNumber() != targetRevisionBeforeScan) {
                return ProjectToolSupport.error("Source or target changed during offset detection; restart the transfer");
            }
            detectedOffset = offsetResult.offset;
            sampleCount = offsetResult.agreementCount;
        }

        if (sourceProgram.getModificationNumber() != sourceRevisionBeforeScan || targetProgram.getModificationNumber() != targetRevisionBeforeScan)
            return ProjectToolSupport.error("Source or target changed while planning; repeat preview");
        // The same bounded representation validates the entire region before any apply.
        TransferResult transferResult = transferLabels(sourceProgram, targetProgram,
            startAddr, endAddr, detectedOffset, true, createFunctions, sizeTolerance,
            sourceFacts, targetFacts, namePolicy, monitor);
        if (!dryRun && transferResult.fatalError == null && transferResult.failures.isEmpty() && transferResult.mismatches.isEmpty()) {
            if (sourceProgram.getModificationNumber() != sourceRevisionBeforeScan || targetProgram.getModificationNumber() != targetRevisionBeforeScan)
                return ProjectToolSupport.error("Source or target changed during preview; repeat preview");
            transferResult = transferLabels(sourceProgram, targetProgram, startAddr, endAddr, detectedOffset,
                false, createFunctions, sizeTolerance, sourceFacts, targetFacts, namePolicy, monitor);
        } else if (!dryRun) {
            transferResult.matched = 0;
            transferResult.fatalError = "Plan validation failed; no mutation started";
        }

        // ========== PHASE C: Report ==========
        return buildReport(sourceProgramName, targetProgramName, startAddrStr, endAddrStr,
            detectedOffset, sampleCount, dryRun, createFunctions, sizeTolerance, transferResult, comparison,
            sourceFacts, targetFacts, planToken);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }
    }

    // ==================== Phase A: Offset Detection ====================

    /**
     * Auto-detect the code offset between source and target by sampling functions
     * and byte-matching their opcode patterns.
     */
    private OffsetResult detectOffset(Program sourceProgram, Program targetProgram,
                                       Address startAddr, Address endAddr,
                                       MatcherContracts.LanguageFacts sourceFacts,
                                       MatcherContracts.LanguageFacts targetFacts,
                                       TaskMonitor monitor) {
        OffsetResult result = new OffsetResult();
        MatcherContracts.RegionDecision comparison = MatcherContracts.regionCompare(sourceFacts, targetFacts);
        if (!comparison.allowed() || comparison.mode() == MatcherContracts.RegionCompareMode.REJECTED) {
            result.error = comparison.message();
            return result;
        }
        boolean vleMask = comparison.mode() == MatcherContracts.RegionCompareMode.POWERPC_VLE_OPCODE_MASK;

        // Collect candidate functions from source: named, >40 bytes
        List<Function> candidates = new ArrayList<>();
        FunctionIterator funcIter = sourceProgram.getFunctionManager().getFunctions(startAddr, true);
        while (funcIter.hasNext() && candidates.size() < OFFSET_SAMPLE_COUNT) {
            Function func = funcIter.next();
            if (func.getEntryPoint().compareTo(endAddr) > 0) break;
            if (!isNamedFunction(func)) continue;
            if (func.getBody().getNumAddresses() < OFFSET_MIN_FUNC_SIZE) continue;
            candidates.add(func);
        }

        if (candidates.isEmpty()) {
            result.error = "No named functions >40 bytes found in source range";
            return result;
        }

        // For each candidate, try to find a matching location in the target
        Memory srcMem = sourceProgram.getMemory();
        Memory tgtMem = targetProgram.getMemory();
        AddressSpace tgtAddrSpace = targetProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionManager tgtFuncMgr = targetProgram.getFunctionManager();

        List<Long> offsets = new ArrayList<>();
        List<String> sampleDetails = new ArrayList<>();

        for (Function srcFunc : candidates) {
            Address srcEntry = srcFunc.getEntryPoint();
            long srcOffset = srcEntry.getOffset();
            long srcSize = srcFunc.getBody().getNumAddresses();

            // Read a 16-byte pattern. VLE uses the shared decoded operand mask; other languages compare exact bytes.
            int patternLen = OFFSET_PATTERN_WORDS * 4;
            byte[] pattern = new byte[patternLen];
            byte[] mask = new byte[patternLen];

            try {
                for (int i = 0; i < patternLen; i++) {
                    pattern[i] = srcMem.getByte(srcEntry.add(i));
                    mask[i] = (byte) 0xFF;
                }
            } catch (MemoryAccessException e) {
                sampleDetails.add(String.format("  SKIP %s: can't read source bytes", srcFunc.getName()));
                continue;
            }

            if (vleMask) {
                var qualified = InstructionMaskBuilder.plan(sourceProgram, srcEntry, patternLen, MatcherContracts.MaskMode.AUTO, monitor);
                if (!qualified.sound() || qualified.mask() == null) {
                    sampleDetails.add("SKIP " + srcFunc.getName() + ": " + qualified.explanation()); continue;
                }
                mask = qualified.mask();
            }

            // Search target within +/- OFFSET_SEARCH_RANGE of source address
            long searchStartOffset = Math.max(0, srcOffset - OFFSET_SEARCH_RANGE);
            long searchEndOffset = srcOffset + OFFSET_SEARCH_RANGE;
            Address searchStart = tgtAddrSpace.getAddress(searchStartOffset);
            Address searchEnd = tgtAddrSpace.getAddress(searchEndOffset);

            // Clamp to valid target memory
            Address tgtMin = tgtMem.getMinAddress();
            Address tgtMax = tgtMem.getMaxAddress();
            if (tgtMin == null || tgtMax == null) {
                result.error = "Target program has no memory";
                return result;
            }
            if (searchStart.compareTo(tgtMin) < 0) searchStart = tgtMin;
            if (searchEnd.compareTo(tgtMax) > 0) searchEnd = tgtMax;

            boolean foundMatch = false;
            try {
                Address matchAddr = tgtMem.findBytes(searchStart, searchEnd, pattern, mask, true, monitor);
                while (matchAddr != null && !foundMatch) {
                    // Check if this is a function entry point
                    Function tgtFunc = tgtFuncMgr.getFunctionAt(matchAddr);
                    if (tgtFunc != null) {
                        // Check size similarity (relaxed for offset detection)
                        long tgtSize = tgtFunc.getBody().getNumAddresses();
                        double sizeRatio = Math.min(srcSize, tgtSize) /
                                           (double) Math.max(srcSize, tgtSize);
                        if (sizeRatio > 0.5 && (!vleMask || compatibleInstructionMask(targetProgram, matchAddr, patternLen, mask, monitor))) {
                            long offset = matchAddr.getOffset() - srcOffset;
                            offsets.add(offset);
                            sampleDetails.add(String.format("  MATCH %s: src=0x%08x tgt=0x%08x offset=%+d (size %d vs %d)",
                                srcFunc.getName(), srcOffset, matchAddr.getOffset(), offset, srcSize, tgtSize));
                            foundMatch = true;
                        }
                    }
                    if (!foundMatch) {
                        matchAddr = tgtMem.findBytes(matchAddr.add(1), searchEnd, pattern, mask, true, monitor);
                    }
                }
            } catch (Exception e) {
                sampleDetails.add(String.format("  ERROR %s: %s", srcFunc.getName(), e.getMessage()));
                continue;
            }

            if (!foundMatch) {
                sampleDetails.add(String.format("  NOMATCH %s: no matching function entry in target", srcFunc.getName()));
            }
        }

        result.sampleDetails = sampleDetails;

        if (offsets.isEmpty()) {
            result.error = "No offset samples found. Target may be missing function definitions.\n" +
                "Consider using create_functions_at_addresses first, or provide code_offset manually.\n" +
                "Sample details:\n" + String.join("\n", sampleDetails);
            return result;
        }

        // Find mode (most common offset)
        Map<Long, Integer> freqMap = new HashMap<>();
        for (Long off : offsets) {
            freqMap.merge(off, 1, Integer::sum);
        }

        long modeOffset = 0;
        int modeCount = 0;
        for (Map.Entry<Long, Integer> entry : freqMap.entrySet()) {
            if (entry.getValue() > modeCount) {
                modeCount = entry.getValue();
                modeOffset = entry.getKey();
            }
        }

        if (modeCount < MIN_AGREEING_SAMPLES) {
            result.error = String.format(
                "Inconsistent offsets: only %d/%d samples agree on offset %+d (need %d).\n" +
                "Offsets found: %s\nSample details:\n%s",
                modeCount, offsets.size(), modeOffset, MIN_AGREEING_SAMPLES,
                freqMap.toString(), String.join("\n", sampleDetails));
            return result;
        }

        result.offset = modeOffset;
        result.agreementCount = modeCount;
        result.totalSamples = offsets.size();
        return result;
    }

    // ==================== Phase B: Verified Transfer ====================

    /**
     * Transfer labels from source to target with size and opcode verification.
     */
    private TransferResult transferLabels(Program sourceProgram, Program targetProgram,
                                           Address startAddr, Address endAddr, long offset,
                                           boolean dryRun, boolean createFunctions,
                                           double sizeTolerance,
                                           MatcherContracts.LanguageFacts sourceFacts,
                                           MatcherContracts.LanguageFacts targetFacts,
                                           String namePolicy,
                                           TaskMonitor monitor) {
        TransferResult result = new TransferResult();
        MatcherContracts.RegionDecision comparison = MatcherContracts.regionCompare(sourceFacts, targetFacts);
        if (!comparison.allowed() || comparison.mode() == MatcherContracts.RegionCompareMode.REJECTED) {
            result.fatalError = comparison.message();
            return result;
        }

        if (!dryRun && targetProgram.getCurrentTransactionInfo() != null) {
            result.fatalError = "Target has an active transaction; retry after it finishes";
            return result;
        }

        Memory srcMem = sourceProgram.getMemory();
        Memory tgtMem = targetProgram.getMemory();
        AddressSpace tgtAddrSpace = targetProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionManager tgtFuncMgr = targetProgram.getFunctionManager();

        int txId = -1;
        long sourceRevision = sourceProgram.getModificationNumber();
        long targetRevision = targetProgram.getModificationNumber();
        String transactionName = "MCP region transfer " + java.util.UUID.randomUUID();
        if (!dryRun) {
            if (!targetProgram.isChangeable()) { result.fatalError = "Target is not changeable"; return result; }
            txId = targetProgram.startTransaction(transactionName);
            var info = targetProgram.getCurrentTransactionInfo();
            if (info != null && info.getOpenSubTransactions().stream().anyMatch(d -> !TransferPlanSupport.ownTransactionDescription(d, transactionName))) {
                targetProgram.endTransaction(txId, true);
                result.fatalError = "Foreign target transaction started; retry preview";
                return result;
            }
            if (targetProgram.getModificationNumber() != targetRevision || sourceProgram.getModificationNumber() != sourceRevision) {
                targetProgram.endTransaction(txId, false);
                result.fatalError = "Program changed before region transaction";
                return result;
            }
        }

        try {
            int consecutiveMismatches = 0;

            FunctionIterator funcIter = sourceProgram.getFunctionManager().getFunctions(startAddr, true);
            while (funcIter.hasNext()) {
                if (Thread.currentThread().isInterrupted() || monitor.isCancelled()) {
                    result.fatalError = "Transfer cancelled; remaining functions not processed";
                    break;
                }
                Function srcFunc = funcIter.next();
                if (srcFunc.getEntryPoint().compareTo(endAddr) > 0) break;
                result.totalSourceFunctions++;
                if (result.totalSourceFunctions > TransferPlanSupport.MAX_TRANSFERS) {
                    result.fatalError = "Region exceeds 500 functions; narrow the address range"; break;
                }

                // Skip unnamed functions
                if (!isNamedFunction(srcFunc)) {
                    result.skippedUnnamed++;
                    continue;
                }

                String srcName = srcFunc.getName();
                Address srcEntry = srcFunc.getEntryPoint();
                long srcOffset = srcEntry.getOffset();
                long srcSize = srcFunc.getBody().getNumAddresses();

                // Compute expected target address
                long tgtOffset;
                try { tgtOffset = Math.addExact(srcOffset, offset); }
                catch (ArithmeticException e) { result.fatalError = "Target address offset overflows"; break; }
                Address tgtAddr;
                try {
                    tgtAddr = tgtAddrSpace.getAddress(tgtOffset);
                } catch (Exception e) {
                    result.addMismatch(srcName, srcEntry, String.format(
                        "target address 0x%08x out of range", tgtOffset));
                    consecutiveMismatches++;
                    checkConsecutiveMismatches(result, consecutiveMismatches, offset);
                    continue;
                }

                // Check if target address is in memory
                if (!tgtMem.contains(tgtAddr)) {
                    result.addMismatch(srcName, srcEntry, String.format(
                        "target 0x%08x not in memory", tgtOffset));
                    consecutiveMismatches++;
                    checkConsecutiveMismatches(result, consecutiveMismatches, offset);
                    continue;
                }

                // Get or create function at target address
                Function tgtFunc = tgtFuncMgr.getFunctionAt(tgtAddr);
                if (tgtFunc == null) {
                    if (createFunctions && !dryRun) {
                        tgtFunc = createFunctionAt(targetProgram, tgtAddr, monitor);
                        if (tgtFunc != null) {
                            result.functionsCreated++;
                        }
                    }
                    if (tgtFunc == null) {
                        if (createFunctions && dryRun) {
                            // In dry run, we can't create the function but we note it would be created
                            result.addDetail(srcName, srcEntry, tgtAddr,
                                "WOULD_CREATE: no function, would create and label");
                            result.matched++;
                            consecutiveMismatches = 0;
                            continue;
                        }
                        result.addFailed(srcName, srcEntry, String.format(
                            "no function at target 0x%08x", tgtOffset));
                        consecutiveMismatches++;
                        checkConsecutiveMismatches(result, consecutiveMismatches, offset);
                        continue;
                    }
                }

                // Skip if already has this name
                if (tgtFunc.getName().equals(srcName)) {
                    result.skippedAlreadyNamed++;
                    consecutiveMismatches = 0;
                    continue;
                }
                if ("default_only".equals(namePolicy)
                        && tgtFunc.getSymbol().getSource() != SourceType.DEFAULT) {
                    result.skippedAlreadyNamed++;
                    consecutiveMismatches = 0;
                    continue;
                }

                // Size verification
                long tgtSize = tgtFunc.getBody().getNumAddresses();
                double sizeRatio = Math.min(srcSize, tgtSize) /
                                   (double) Math.max(srcSize, tgtSize);
                if (sizeRatio < (1.0 - sizeTolerance)) {
                    result.addMismatch(srcName, srcEntry, String.format(
                        "size mismatch: src=%d tgt=%d ratio=%.2f (threshold=%.2f)",
                        srcSize, tgtSize, sizeRatio, 1.0 - sizeTolerance));
                    consecutiveMismatches++;
                    checkConsecutiveMismatches(result, consecutiveMismatches, offset);
                    continue;
                }

                // Opcode verification — re-run the architecture guard; never apply VLE masks otherwise.
                int compareBytes = (int) Math.min(Math.min(srcSize, tgtSize), VERIFY_MAX_BYTES);
                if (comparison.mode() == MatcherContracts.RegionCompareMode.POWERPC_VLE_OPCODE_MASK) {
                    compareBytes = (compareBytes / 4) * 4;
                }
                if (compareBytes >= 1 && (comparison.mode() != MatcherContracts.RegionCompareMode.POWERPC_VLE_OPCODE_MASK || compareBytes >= 4)) {
                    double opcodeMatch = computeOpcodeMatch(srcMem, srcEntry, tgtMem, tgtAddr, compareBytes,
                        sourceFacts, targetFacts);
                    double requiredMatch = comparison.mode() == MatcherContracts.RegionCompareMode.POWERPC_VLE_OPCODE_MASK ? OPCODE_MATCH_THRESHOLD : 1.0;
                    if (opcodeMatch < requiredMatch) {
                        result.addMismatch(srcName, srcEntry, String.format(
                            "opcode mismatch: %.0f%% match (threshold=%.0f%%), compared %d bytes (%s)",
                            opcodeMatch * 100, OPCODE_MATCH_THRESHOLD * 100, compareBytes, comparison.mode().name()));
                        consecutiveMismatches++;
                        checkConsecutiveMismatches(result, consecutiveMismatches, offset);
                        continue;
                    }
                }

                // Verified — apply label
                consecutiveMismatches = 0;

                if (!dryRun) {
                    try {
                        tgtFunc.setName(srcName, SourceType.IMPORTED);
                    } catch (Exception e) {
                        result.addFailed(srcName, srcEntry,
                            "rename failed: " + e.getMessage());
                        continue;
                    }
                }

                result.matched++;
                result.addDetail(srcName, srcEntry, tgtAddr,
                    String.format("%s (size %d→%d, ratio=%.2f)",
                        dryRun ? "WOULD_LABEL" : "LABELED", srcSize, tgtSize, sizeRatio));
            }

            if (!dryRun && txId >= 0) {
                if (Thread.currentThread().isInterrupted() || monitor.isCancelled()) result.fatalError = "Transfer cancelled";
                if (sourceProgram != targetProgram && sourceProgram.getModificationNumber() != sourceRevision)
                    result.fatalError = "Source changed during transfer";
                boolean commit = result.failures.isEmpty() && result.mismatches.isEmpty() && result.fatalError == null;
                targetProgram.endTransaction(txId, commit);
                txId = -1;
                result.committed = commit;
                if (!commit) result.recordRollback();
            }

        } catch (Exception e) {
            if (!dryRun && txId >= 0) {
                targetProgram.endTransaction(txId, false);
                result.recordRollback();
            }
            result.fatalError = "Transaction failed: " + e.getMessage();
        }

        return result;
    }

    /**
     * Compare bytes between source and target. PowerPC VLE uses a decoded instruction operand
     * mask only after {@link MatcherContracts#regionCompare} qualifies both programs.
     * Matching non-VLE languages compare exact bytes. This method never applies VLE
     * masks when the guard rejects or selects exact-byte mode.
     */
    private double computeOpcodeMatch(Memory srcMem, Address srcAddr,
                                       Memory tgtMem, Address tgtAddr, int numBytes,
                                       MatcherContracts.LanguageFacts sourceFacts,
                                       MatcherContracts.LanguageFacts targetFacts) {
        MatcherContracts.RegionDecision comparison = MatcherContracts.regionCompare(sourceFacts, targetFacts);
        if (!comparison.allowed() || comparison.mode() == MatcherContracts.RegionCompareMode.REJECTED) {
            throw new IllegalStateException("Region opcode compare invoked without architecture qualification: "
                + comparison.message());
        }

        try {
            byte[] mask = new byte[numBytes]; java.util.Arrays.fill(mask, (byte)0xff);
            if (comparison.mode() == MatcherContracts.RegionCompareMode.POWERPC_VLE_OPCODE_MASK) {
                var qualified = InstructionMaskBuilder.plan(srcMem.getProgram(), srcAddr, numBytes,
                    MatcherContracts.MaskMode.AUTO, TaskMonitor.DUMMY);
                if (!qualified.sound() || qualified.mask() == null) return 0;
                mask = qualified.mask();
                if (!compatibleInstructionMask(tgtMem.getProgram(), tgtAddr, numBytes, mask, TaskMonitor.DUMMY)) return 0;
            }
            for (int i = 0; i < numBytes; i++) {
                if (Thread.currentThread().isInterrupted()) return 0;
                if ((srcMem.getByte(srcAddr.add(i)) & mask[i]) != (tgtMem.getByte(tgtAddr.add(i)) & mask[i])) return 0;
            }
            return numBytes > 0 ? 1.0 : 0;
        } catch (Exception e) { return 0; }
    }

    private static boolean compatibleInstructionMask(Program program, Address address, int length, byte[] expected, TaskMonitor monitor) {
        var qualified = InstructionMaskBuilder.plan(program, address, length, MatcherContracts.MaskMode.AUTO, monitor);
        return qualified.sound() && java.util.Arrays.equals(expected, qualified.mask());
    }

    /**
     * Create a function at the given address by disassembling first, then creating.
     */
    private Function createFunctionAt(Program program, Address addr, TaskMonitor monitor) {
        // Disassemble bytes
        DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
        disCmd.applyTo(program, monitor);

        // Create function
        CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
        boolean ok = funcCmd.applyTo(program, monitor);
        if (ok) {
            return program.getFunctionManager().getFunctionAt(addr);
        }
        return null;
    }

    /**
     * Check if consecutive mismatches exceed threshold and add a warning.
     */
    private void checkConsecutiveMismatches(TransferResult result, int count, long offset) {
        if (count == CONSECUTIVE_MISMATCH_WARN) {
            result.addWarning(String.format(
                "WARNING: %d consecutive mismatches detected — offset %+d may have shifted in this region",
                count, offset));
        }
    }

    /**
     * Check if a function has a real (non-default) name.
     */
    private boolean isNamedFunction(Function func) {
        return func.getSymbol().getSource() != SourceType.DEFAULT;
    }

    // ==================== Phase C: Report ====================

    private McpSchema.CallToolResult buildReport(String sourceName, String targetName,
                                                   String startAddr, String endAddr,
                                                   long offset, int sampleCount,
                                                   boolean dryRun, boolean createFunctions,
                                                   double sizeTolerance, TransferResult tr,
                                                   MatcherContracts.RegionDecision comparison,
                                                   MatcherContracts.LanguageFacts sourceFacts,
                                                   MatcherContracts.LanguageFacts targetFacts,
                                                   String planToken) {
        StringBuilder report = new StringBuilder();
        report.append("Bulk Region Transfer Report\n");
        report.append("===========================\n");
        report.append("Source: ").append(sourceName).append("\n");
        report.append("Target: ").append(targetName).append("\n");
        report.append("Range: ").append(startAddr).append(" — ").append(endAddr).append("\n");
        report.append("Comparison: ").append(comparison.mode().name()).append(" — ").append(comparison.message()).append("\n");
        if (dryRun) report.append("MODE: DRY RUN (no changes applied)\n");
        report.append("\n");

        // Offset info
        report.append("Offset: ").append(String.format("%+d (0x%X)", offset, Math.abs(offset)));
        if (sampleCount > 0) {
            report.append(String.format(" (auto-detected, %d samples agreed)", sampleCount));
        } else if (sampleCount < 0) {
            report.append(" (user-provided)");
        }
        report.append("\n\n");

        // Summary
        report.append("Summary:\n");
        report.append("  Total source functions in range: ").append(tr.totalSourceFunctions).append("\n");
        report.append("  Matched and labeled: ").append(tr.matched).append("\n");
        report.append("  Skipped (already named): ").append(tr.skippedAlreadyNamed).append("\n");
        report.append("  Skipped (unnamed source): ").append(tr.skippedUnnamed).append("\n");
        report.append("  Mismatched (failed verification): ").append(tr.mismatches.size()).append("\n");
        report.append("  Failed (no function / error): ").append(tr.failures.size()).append("\n");
        if (createFunctions && !dryRun) {
            report.append("  Functions created at target: ").append(tr.functionsCreated).append("\n");
        }
        report.append("  Labels rolled back: ").append(tr.labelsRolledBack).append("\n");
        report.append("  Functions rolled back: ").append(tr.functionsRolledBack).append("\n");
        report.append("\n");

        // Warnings
        if (!tr.warnings.isEmpty()) {
            report.append("Warnings:\n");
            for (String warning : tr.warnings) {
                report.append("  ").append(warning).append("\n");
            }
            report.append("\n");
        }

        // Mismatches (always show)
        if (!tr.mismatches.isEmpty()) {
            report.append("Mismatches (failed verification):\n");
            for (String m : tr.mismatches) {
                report.append("  ").append(m).append("\n");
            }
            report.append("\n");
        }

        // Failures
        if (!tr.failures.isEmpty()) {
            report.append("Failures:\n");
            for (String f : tr.failures) {
                report.append("  ").append(f).append("\n");
            }
            report.append("\n");
        }

        if (tr.fatalError != null) {
            report.append("FATAL ERROR: ").append(tr.fatalError).append("\n");
        }

        Map<String, Object> structured = new LinkedHashMap<>();
        structured.put("source_program", sourceName);
        structured.put("target_program", targetName);
        structured.put("preview_token", planToken);
        structured.put("dry_run", dryRun);
        structured.put("committed", tr.committed);
        structured.put("matched", tr.matched);
        structured.put("would_commit", dryRun ? tr.matched : 0);
        structured.put("labels_committed", tr.committed ? tr.matched : 0);
        structured.put("preserved_or_unchanged", tr.skippedAlreadyNamed);
        structured.put("source_unnamed", tr.skippedUnnamed);
        structured.put("functions_created", tr.functionsCreated);
        structured.put("labels_rolled_back", tr.labelsRolledBack);
        structured.put("functions_rolled_back", tr.functionsRolledBack);
        structured.put("failures", tr.failures);
        structured.put("mismatches", tr.mismatches);
        structured.put("details", tr.details);
        structured.put("fatal_error", tr.fatalError == null ? "" : tr.fatalError);
        structured.put("comparison_mode", comparison.mode().name().toLowerCase());
        structured.put("comparison_note", comparison.message());
        structured.put("source_language", sourceFacts.languageId());
        structured.put("target_language", targetFacts.languageId());
        return ProjectToolSupport.result(structured, tr.fatalError != null || !tr.failures.isEmpty() || !tr.mismatches.isEmpty() || !dryRun && !tr.committed);
    }

    private String planToken(Program source, Program target, String start, String end, Long offset,
            boolean createFunctions, double tolerance, String namePolicy) {
        try {
            String value = String.join("|", "bulk_region_transfer", ProgramIdentity.id(source),
                ProgramIdentity.id(target), Integer.toUnsignedString(System.identityHashCode(source)), Integer.toUnsignedString(System.identityHashCode(target)), Long.toString(source.getModificationNumber()),
                Long.toString(target.getModificationNumber()), start, end,
                String.valueOf(offset), Boolean.toString(createFunctions), Double.toString(tolerance), namePolicy);
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException("Unable to fingerprint region transfer plan", e); }
    }

    // ==================== Helpers ====================



    // ==================== Result Classes ====================

    private static class OffsetResult {
        long offset;
        int agreementCount;
        int totalSamples;
        String error;
        List<String> sampleDetails;
    }

    private static class TransferResult {
        int totalSourceFunctions = 0;
        int matched = 0;
        int skippedAlreadyNamed = 0;
        int skippedUnnamed = 0;
        int functionsCreated = 0;
        int labelsRolledBack = 0;
        int functionsRolledBack = 0;
        boolean committed = false;
        String fatalError = null;

        List<String> mismatches = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        List<String> details = new ArrayList<>();

        void recordRollback() {
            labelsRolledBack = matched;
            functionsRolledBack = functionsCreated;
            matched = 0;
            functionsCreated = 0;
            details.replaceAll(detail -> detail.contains("LABELED") ? "ROLLED BACK: " + detail : detail);
        }

        void addMismatch(String funcName, Address srcAddr, String reason) {
            mismatches.add(String.format("%s @ 0x%08x: %s",
                funcName, srcAddr.getOffset(), reason));
        }

        void addFailed(String funcName, Address srcAddr, String reason) {
            failures.add(String.format("%s @ 0x%08x: %s",
                funcName, srcAddr.getOffset(), reason));
        }

        void addWarning(String warning) {
            warnings.add(warning);
        }

        void addDetail(String funcName, Address srcAddr, Address tgtAddr, String info) {
            details.add(String.format("%s: 0x%08x → 0x%08x %s",
                funcName, srcAddr.getOffset(), tgtAddr.getOffset(), info));
        }
    }
}
