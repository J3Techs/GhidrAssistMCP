/*
 * MCP tool that matches functions between binaries using byte patterns.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Matches functions between two open programs using byte patterns.
 * {@code mask_mode=none} is a raw 0xFF mask on any architecture.
 * {@code auto}/{@code aggressive} use {@link InstructionMaskBuilder}; unsupported
 * plans error instead of applying VLE heuristics or falling back to exact bytes.
 * Confidence is ranking evidence, not an approval probability, and a result cap
 * does not establish uniqueness.
 */
public class FunctionByteMatcherTool implements McpTool {

    @Override
    public String getName() {
        return "function_byte_matcher";
    }

    @Override
    public String getDescription() {
        return "Match a function from one program to another by byte pattern. "
            + "Extracts entry bytes from the source and searches executable loaded memory in the target. "
            + "mask_mode=none is raw bytes on any architecture. mask_mode=auto/aggressive ask InstructionMaskBuilder "
            + "for instruction-qualified relocatable-operand masks; unsupported architectures or unsound plans error "
            + "(they do not silently apply VLE 4-byte heuristics or fall back to exact bytes). "
            + "Ranking scores are not approval probabilities. A hit cap cannot establish uniqueness. "
            + "Use native Version Tracking or BSim when masked matching is unsupported.";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "source_function", Map.of("type", "string", "description", "Function name or address in the source program"),
                "source_program", Map.of("type", "string", "description", "Exact source program_id or unique name (with known symbols)"),
                "target_program", Map.of("type", "string", "description", "Exact target program_id or unique name to search in"),
                "match_bytes", Map.of("type", "integer", "minimum", 1, "maximum", 65536, "description", "Number of entry bytes to use for matching (default 24)", "default", 24),
                "mask_mode", Map.of("type", "string", "enum", List.of("none", "auto", "aggressive"),
                    "description", "none: raw 0xFF mask (any architecture). auto/aggressive: InstructionMaskBuilder relocatable-operand masks; unsupported plans error instead of VLE heuristics or exact-byte fallback. Default: auto",
                    "default", "auto"),
                "limit", Map.of("type", "integer", "minimum", 1, "maximum", QueryPageBounds.MAX_LIMIT,
                    "description", "Maximum candidates to return (default 20). Hitting the cap does not imply uniqueness.",
                    "default", MatcherContracts.DEFAULT_BYTE_MATCH_CAP),
                "start_address", Map.of("type", "string", "description", "Optional inclusive start of the target scan range"),
                "end_address", Map.of("type", "string", "description", "Optional inclusive end of the target scan range")
            ),
            List.of("source_function", "source_program", "target_program"), null, null, null);
    }

    @Override
    public Map<String, Object> getOutputSchema() {
        Map<String, Object> functionRefProps = new LinkedHashMap<>();
        functionRefProps.put("name", Map.of("type", "string"));
        functionRefProps.put("entry", Map.of("type", "string"));
        functionRefProps.put("size", Map.of("type", "integer", "minimum", 0));
        Map<String, Object> functionRef = MatcherContracts.objectSchema(functionRefProps, List.of("name", "entry", "size"));
        Map<String, Object> programRefProps = new LinkedHashMap<>();
        programRefProps.put("program_id", Map.of("type", "string"));
        programRefProps.put("name", Map.of("type", "string"));
        programRefProps.put("modification_number", Map.of("type", "string"));
        programRefProps.put("language", Map.of("type", "string"));
        programRefProps.put("processor", Map.of("type", "string"));
        Map<String, Object> programRef = MatcherContracts.objectSchema(programRefProps,
            List.of("program_id", "name", "modification_number", "language"));
        Map<String, Object> candidateProps = new LinkedHashMap<>();
        candidateProps.put("address", Map.of("type", "string"));
        candidateProps.put("space", Map.of("type", "string"));
        candidateProps.put("containing_function", MatcherContracts.nullable(functionRef));
        candidateProps.put("at_entry", Map.of("type", "boolean"));
        candidateProps.put("target_name", MatcherContracts.nullable(Map.of("type", "string")));
        candidateProps.put("target_name_source", MatcherContracts.nullable(Map.of("type", "string")));
        candidateProps.put("source_size", Map.of("type", "integer"));
        candidateProps.put("target_size", MatcherContracts.nullable(Map.of("type", "integer")));
        candidateProps.put("size_delta", MatcherContracts.nullable(Map.of("type", "integer")));
        candidateProps.put("size_ratio", MatcherContracts.nullable(Map.of("type", "number")));
        candidateProps.put("ranking_score", Map.of("type", "number"));
        candidateProps.put("confidence", Map.of("type", "number",
            "description", "Ranking evidence only; not an approval probability"));
        candidateProps.put("score_role", Map.of("type", "string"));
        candidateProps.put("score_explanation", Map.of("type", "string"));
        Map<String, Object> candidate = MatcherContracts.objectSchema(candidateProps,
            List.of("address", "at_entry", "ranking_score", "confidence", "score_role", "score_explanation"));
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("source_program", programRef);
        properties.put("target_program", programRef);
        properties.put("source_function", Map.of("type", "string"));
        properties.put("source_entry", Map.of("type", "string"));
        properties.put("source_size", Map.of("type", "integer"));
        properties.put("mask_mode", Map.of("type", "string"));
        properties.put("comparison_mode", Map.of("type", "string", "enum", List.of("raw", "relocatable_operands"),
            "description", "Actual comparison used: raw (0xFF / builder RAW) or relocatable_operands. Never pretends VLE on x86/ARM."));
        properties.put("comparison_note", Map.of("type", "string"));
        properties.put("pattern_hex", Map.of("type", "string"));
        properties.put("mask_hex", Map.of("type", "string"));
        properties.put("masked_byte_ratio", Map.of("type", "number"));
        properties.put("scan_scope", Map.of("type", "string"));
        properties.put("blocks_scanned", Map.of("type", "integer", "minimum", 0));
        properties.put("candidate_count", Map.of("type", "integer", "minimum", 0));
        properties.put("result_cap", Map.of("type", "integer", "minimum", 1));
        properties.put("scan_complete", Map.of("type", "boolean"));
        properties.put("scan_truncated", Map.of("type", "boolean"));
        properties.put("cancelled", Map.of("type", "boolean"));
        properties.put("unique", Map.of("type", "boolean", "description", "True only for a single complete unscapped hit; a cap never implies uniqueness"));
        properties.put("candidates", Map.of("type", "array", "items", candidate, "maxItems", QueryPageBounds.MAX_LIMIT));
        return MatcherContracts.objectSchema(properties, List.of(
            "source_program", "target_program", "mask_mode", "comparison_mode", "pattern_hex",
            "candidate_count", "result_cap", "scan_complete", "scan_truncated", "cancelled", "unique", "candidates"));
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .isError(true).addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        return execute(arguments, currentProgram, backend, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, McpTask task) {
        if (backend == null) {
            return ProjectToolSupport.error("Backend context not available");
        }

        String sourceFuncId = (String) arguments.get("source_function");
        String sourceProgramName = (String) arguments.get("source_program");
        String targetProgramName = (String) arguments.get("target_program");
        final int matchBytes;
        final int limit;
        String maskModeRaw = arguments.get("mask_mode") instanceof String s ? s : "auto";
        final MatcherContracts.MaskMode mode;

        try {
            matchBytes = QueryPageBounds.integer(arguments, "match_bytes", 24, 1, 65536);
            limit = QueryPageBounds.integer(arguments, "limit", MatcherContracts.DEFAULT_BYTE_MATCH_CAP, 1, QueryPageBounds.MAX_LIMIT);
            mode = MatcherContracts.parseMaskMode(maskModeRaw);
        } catch (IllegalArgumentException e) {
            return ProjectToolSupport.error(e.getMessage());
        }

        TaskMonitor monitor = task == null ? TaskMonitor.DUMMY : new McpTaskMonitor(task, 0, 100, "Function byte matcher");

        try (ProgramSelection.Lease sourceLease = ProgramSelection.lease(backend, sourceProgramName, currentProgram);
             ProgramSelection.Lease targetLease = ProgramSelection.lease(backend, targetProgramName, currentProgram)) {
            Program sourceProgram = sourceLease.program();
            Program targetProgram = targetLease.program();

            Function sourceFunc = FunctionLookup.resolve(sourceProgram, sourceFuncId);
            if (sourceFunc == null) {
                return ProjectToolSupport.error("Function not found in source program: " + sourceFuncId);
            }

            Address rangeStart = parseOptionalAddress(targetProgram, arguments.get("start_address"), "start_address");
            Address rangeEnd = parseOptionalAddress(targetProgram, arguments.get("end_address"), "end_address");
            String rangeError = InstructionMaskBuilder.validateScanRange(rangeStart, rangeEnd);
            if (rangeError != null) return ProjectToolSupport.error(rangeError);

            long sourceFuncSize = sourceFunc.getBody().getNumAddresses();
            if (sourceFuncSize < 1) {
                return ProjectToolSupport.error("Source function has no readable entry bytes");
            }
            int bytesToRead = matchBytes;
            if (bytesToRead > sourceFuncSize && arguments.get("match_bytes") != null) {
                return ProjectToolSupport.error("getBytes requested " + bytesToRead
                    + " but the function body is only " + sourceFuncSize + " bytes");
            }
            bytesToRead = (int) Math.min(bytesToRead, sourceFuncSize);
            if (bytesToRead > InstructionMaskBuilder.MAX_PATTERN_BYTES) {
                return ProjectToolSupport.error("match_bytes exceeds " + InstructionMaskBuilder.MAX_PATTERN_BYTES);
            }

            Memory sourceMem = sourceProgram.getMemory();
            byte[] sourceBytes = new byte[bytesToRead];
            byte[] mask = new byte[bytesToRead];
            Address entry = sourceFunc.getEntryPoint();
            try {
                if (!sourceFunc.getBody().contains(entry, entry.addNoWrap(bytesToRead - 1L)))
                    return ProjectToolSupport.error("Entry byte window crosses a gap in the source function body");
            } catch (ghidra.program.model.address.AddressOverflowException e) {
                return ProjectToolSupport.error("Entry byte window exceeds the source address space");
            }
            try {
                int got = sourceMem.getBytes(entry, sourceBytes);
                if (got < bytesToRead) {
                    return ProjectToolSupport.error("getBytes returned " + got + " of " + bytesToRead
                        + " requested source bytes");
                }
                Arrays.fill(mask, (byte) 0xFF);
            } catch (MemoryAccessException e) {
                return ProjectToolSupport.error("Failed to read source function bytes: " + e.getMessage());
            }

            String comparisonMode;
            String comparisonNote;
            InstructionMaskBuilder.Plan plan = null;
            if (mode == MatcherContracts.MaskMode.NONE) {
                comparisonMode = "raw";
                comparisonNote = "mask_mode=none uses exact raw-byte comparison; it is not instruction-qualified.";
            } else {
                try {
                    plan = InstructionMaskBuilder.plan(sourceProgram, sourceFunc, sourceBytes, mode, monitor);
                } catch (Exception e) {
                    if (monitor.isCancelled() || e instanceof CancelledException) {
                        ScanOutcome cancelled = new ScanOutcome();
                        cancelled.cancelled = true;
                        cancelled.finishedAllRanges = false;
                        return buildResult(sourceProgram, targetProgram, sourceFunc, sourceFuncSize, mode,
                            "raw", "Mask planning cancelled", sourceBytes, mask, cancelled, limit);
                    }
                    return ProjectToolSupport.error(e.getMessage() == null
                        ? "Instruction mask planning failed" : e.getMessage());
                }
                if (monitor.isCancelled()) {
                    ScanOutcome cancelled = new ScanOutcome();
                    cancelled.cancelled = true;
                    cancelled.finishedAllRanges = false;
                    return buildResult(sourceProgram, targetProgram, sourceFunc, sourceFuncSize, mode,
                        "raw", "Mask planning cancelled", sourceBytes, mask, cancelled, limit);
                }
                MaskPlan applied = applyBuilderPlan(mode, plan, sourceBytes, mask);
                if (applied.error != null) {
                    return ProjectToolSupport.error(applied.error);
                }
                mask = applied.mask;
                comparisonMode = applied.comparisonMode;
                comparisonNote = applied.comparisonNote;
                if (mask.length < sourceBytes.length) {
                    sourceBytes = Arrays.copyOf(sourceBytes, mask.length);
                }
                String targetErr = InstructionMaskBuilder.maskedTargetError(
                    sourceProgram, entry, sourceBytes.length, plan, targetProgram, rangeStart, rangeEnd);
                if (targetErr != null) return ProjectToolSupport.error(targetErr);
            }

            final InstructionMaskBuilder.Plan candidatePlan = plan;
            ScanOutcome scan = searchTarget(targetProgram, sourceBytes, mask, sourceFuncSize, limit,
                rangeStart, rangeEnd, monitor, candidatePlan);
            return buildResult(sourceProgram, targetProgram, sourceFunc, sourceFuncSize, mode,
                comparisonMode, comparisonNote, sourceBytes, mask, scan, limit);
        } catch (IllegalArgumentException e) {
            return ProjectToolSupport.error(e.getMessage());
        }
    }

    private ScanOutcome searchTarget(Program targetProgram, byte[] sourceBytes, byte[] mask,
            long sourceFuncSize, int limit, Address rangeStart, Address rangeEnd, TaskMonitor monitor,
            InstructionMaskBuilder.Plan candidatePlan) {
        ScanOutcome outcome = new ScanOutcome();
        Memory targetMem = targetProgram.getMemory();
        List<MemoryBlock> blocks = scannableBlocks(targetProgram, rangeStart, rangeEnd);
        outcome.blocksScanned = 0;
        try {
            for (int b = 0; b < blocks.size(); b++) {
                monitor.checkCancelled();
                MemoryBlock block = blocks.get(b);
                Address searchStart = block.getStart();
                Address searchEnd = block.getEnd();
                if (rangeStart != null && rangeStart.getAddressSpace().equals(searchStart.getAddressSpace())
                        && rangeStart.compareTo(searchStart) > 0) {
                    searchStart = rangeStart;
                }
                if (rangeEnd != null && rangeEnd.getAddressSpace().equals(searchEnd.getAddressSpace())
                        && rangeEnd.compareTo(searchEnd) < 0) {
                    searchEnd = rangeEnd;
                }
                if (searchStart.compareTo(searchEnd) > 0) continue;
                outcome.blocksScanned++;

                Address addr = searchStart;
                while (addr != null && addr.compareTo(searchEnd) <= 0) {
                    monitor.checkCancelled();
                    Address hit = targetMem.findBytes(addr, searchEnd, sourceBytes, mask, true, monitor);
                    if (hit == null) break;
                    if (outcome.matches.size() >= limit) {
                        outcome.moreExist = true;
                        outcome.finishedAllRanges = false;
                        return outcome;
                    }
                    if (candidatePlan != null && candidatePlan.kind() == InstructionMaskBuilder.Kind.RELOCATABLE_OPERANDS
                            && !InstructionMaskBuilder.acceptCandidate(candidatePlan, targetProgram, hit)) {
                        try { addr = hit.add(1); } catch (AddressOutOfBoundsException e) { break; }
                        continue;
                    }
                    Function containing = targetProgram.getFunctionManager().getFunctionContaining(hit);
                    Function atEntry = targetProgram.getFunctionManager().getFunctionAt(hit);
                    Score score = calculateScore(sourceBytes, mask, sourceFuncSize, containing, atEntry);
                    outcome.matches.add(new MatchResult(hit, containing, atEntry, score.value, score.explanation));
                    try {
                        addr = hit.add(1);
                    } catch (AddressOutOfBoundsException e) {
                        break;
                    }
                }
            }
            outcome.finishedAllRanges = true;
        } catch (CancelledException e) {
            outcome.cancelled = true;
            outcome.finishedAllRanges = false;
        }
        return outcome;
    }

    private static List<MemoryBlock> scannableBlocks(Program program, Address rangeStart, Address rangeEnd) {
        List<MemoryBlock> blocks = new ArrayList<>();
        long total = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            AddressSpace space = block.getStart().getAddressSpace();
            if (!MatcherContracts.isDefaultScanSpace(space.isLoadedMemorySpace(),
                    "hash".equalsIgnoreCase(space.getName()),
                    block.isExecute(), block.isInitialized())) {
                continue;
            }
            if (rangeStart != null && !rangeStart.getAddressSpace().equals(space)) continue;
            if (rangeEnd != null && !rangeEnd.getAddressSpace().equals(space)) continue;
            Address lo = block.getStart();
            Address hi = block.getEnd();
            if (rangeStart != null && rangeStart.compareTo(lo) > 0) lo = rangeStart;
            if (rangeEnd != null && rangeEnd.compareTo(hi) < 0) hi = rangeEnd;
            if (lo.compareTo(hi) > 0) continue;
            total += hi.subtract(lo) + 1;
            if (total > InstructionMaskBuilder.MAX_SCAN_BYTES)
                throw new IllegalArgumentException("Executable scan range exceeds 1 MiB; reduce start_address/end_address");
            blocks.add(block);
        }
        return blocks;
    }

    private static Address parseOptionalAddress(Program program, Object raw, String name) {
        if (raw == null) return null;
        if (!(raw instanceof String value) || value.isBlank()) throw new IllegalArgumentException(name + " must be a nonblank string");
        Address address = program.getAddressFactory().getAddress(value.trim());
        if (address == null) throw new IllegalArgumentException("Invalid " + name + ": " + value);
        return address;
    }

    /**
     * Apply an instruction-qualified plan. Does not call {@link MatcherContracts#qualify};
     * x86/ARM relocatable-operand masks are allowed when the builder returns them.
     */
    private static MaskPlan applyBuilderPlan(MatcherContracts.MaskMode mode, InstructionMaskBuilder.Plan plan,
            byte[] sourceBytes, byte[] fallbackMask) {
        if (plan == null || plan.kind() == InstructionMaskBuilder.Kind.UNSUPPORTED || !plan.sound()) {
            return MaskPlan.error(unsupportedMaskMessage(mode, plan));
        }
        byte[] planned = plan.mask();
        String note = plan.explanation() == null ? "" : plan.explanation();
        if (plan.kind() == InstructionMaskBuilder.Kind.RELOCATABLE_OPERANDS) {
            if (planned == null || planned.length < 1 || planned.length > sourceBytes.length) {
                return MaskPlan.error(unsupportedMaskMessage(mode, plan));
            }
            return new MaskPlan(planned.clone(), "relocatable_operands", note, null);
        }
        if (plan.kind() == InstructionMaskBuilder.Kind.RAW) {
            if (planned == null) {
                return new MaskPlan(fallbackMask, "raw", note, null);
            }
            if (planned.length < 1 || planned.length > sourceBytes.length) {
                return MaskPlan.error(unsupportedMaskMessage(mode, plan));
            }
            return new MaskPlan(planned.clone(), "raw", note, null);
        }
        return MaskPlan.error(unsupportedMaskMessage(mode, plan));
    }

    private static String unsupportedMaskMessage(MatcherContracts.MaskMode mode, InstructionMaskBuilder.Plan plan) {
        String explanation = plan == null || plan.explanation() == null || plan.explanation().isBlank()
            ? "mask_mode=" + mode.wireName()
                + " cannot build an instruction-qualified relocatable-operand mask for this function."
            : plan.explanation();
        String lower = explanation.toLowerCase(Locale.ROOT);
        if (lower.contains("bsim") || lower.contains("version tracking") || lower.contains("mask_mode=none")) {
            return explanation;
        }
        return explanation + " Use mask_mode=none, native Version Tracking, or BSim. "
            + "Masked comparison does not fall back to exact bytes or PowerPC VLE heuristics.";
    }

    private static McpSchema.CallToolResult buildResult(Program sourceProgram, Program targetProgram,
            Function sourceFunc, long sourceFuncSize, MatcherContracts.MaskMode mode,
            String comparisonMode, String comparisonNote, byte[] sourceBytes, byte[] mask,
            ScanOutcome scan, int limit) {
        MatcherContracts.ScanStatus status = MatcherContracts.scanStatus(
            scan.matches.size(), limit, scan.moreExist, scan.cancelled, scan.finishedAllRanges);
        scan.matches.sort((a, b) -> Double.compare(b.rankingScore, a.rankingScore));

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("source_program", MatcherContracts.programRef(sourceProgram));
        body.put("target_program", MatcherContracts.programRef(targetProgram));
        body.put("source_function", sourceFunc.getName(true));
        body.put("source_entry", sourceFunc.getEntryPoint().toString());
        body.put("source_size", sourceFuncSize);
        body.put("mask_mode", mode.wireName());
        body.put("comparison_mode", comparisonMode);
        body.put("comparison_note", comparisonNote);
        body.put("pattern_hex", bytesToHex(sourceBytes, mask));
        body.put("mask_hex", maskToHex(mask));
        body.put("masked_byte_ratio", maskedRatio(mask));
        body.put("scan_scope", "executable_loaded_memory");
        body.put("blocks_scanned", scan.blocksScanned);
        body.putAll(MatcherContracts.scanFields(status));
        List<Map<String, Object>> candidates = new ArrayList<>();
        for (MatchResult match : scan.matches) {
            candidates.add(candidateRecord(match, sourceFuncSize));
        }
        body.put("candidates", candidates);

        String summary = "Function byte match: " + scan.matches.size() + " candidate(s), unique="
            + status.unique() + ", scan_complete=" + status.scanComplete()
            + ", scan_truncated=" + status.scanTruncated() + ". Ranking scores are not approval probabilities.";
        return BatchQuerySupport.boundedResult(body);
    }

    private Score calculateScore(byte[] sourceBytes, byte[] mask, long sourceFuncSize,
            Function containingFunc, Function atEntry) {
        double score = 0.5;
        StringBuilder explanation = new StringBuilder("Ranking evidence only (not an approval probability): base 0.50");
        Long targetSize = null;
        if (atEntry != null) {
            score += 0.25;
            explanation.append("; +0.25 at function entry");
            targetSize = atEntry.getBody().getNumAddresses();
            double sizeRatio = Math.min(sourceFuncSize, targetSize) / (double) Math.max(sourceFuncSize, targetSize);
            score += sizeRatio * 0.2;
            explanation.append(String.format("; +%.2f size ratio %.2f", sizeRatio * 0.2, sizeRatio));
            if (sizeRatio < 0.5) {
                score -= 0.1;
                explanation.append("; -0.10 large size difference");
            }
        } else {
            explanation.append("; not at function entry");
            if (containingFunc != null) targetSize = containingFunc.getBody().getNumAddresses();
        }
        double specificity = 1.0 - maskedRatio(mask);
        score += specificity * 0.05;
        explanation.append(String.format("; +%.2f pattern specificity", specificity * 0.05));
        return new Score(Math.min(score, 1.0), explanation.toString());
    }

    private static Map<String, Object> candidateRecord(MatchResult match, long sourceFuncSize) {
        Map<String, Object> item = new LinkedHashMap<>();
        Function named = match.atEntry != null ? match.atEntry : match.containing;
        Long targetSize = match.atEntry != null ? match.atEntry.getBody().getNumAddresses()
            : (match.containing != null ? match.containing.getBody().getNumAddresses() : null);
        item.put("address", match.address.toString());
        item.put("space", match.address.getAddressSpace().getName());
        if (match.containing != null) {
            Map<String, Object> containing = new LinkedHashMap<>();
            containing.put("name", match.containing.getName(true));
            containing.put("entry", match.containing.getEntryPoint().toString());
            containing.put("size", match.containing.getBody().getNumAddresses());
            item.put("containing_function", containing);
        } else {
            item.put("containing_function", null);
        }
        item.put("at_entry", match.atEntry != null);
        item.put("target_name", named == null ? null : named.getName(true));
        item.put("target_name_source", named == null ? null : named.getSymbol().getSource().toString());
        item.put("source_size", sourceFuncSize);
        item.put("target_size", targetSize);
        item.put("size_delta", targetSize == null ? null : targetSize - sourceFuncSize);
        item.put("size_ratio", targetSize == null || Math.max(sourceFuncSize, targetSize) == 0 ? null
            : Math.min(sourceFuncSize, targetSize) / (double) Math.max(sourceFuncSize, targetSize));
        item.put("ranking_score", match.rankingScore);
        item.put("confidence", match.rankingScore);
        item.put("score_role", "ranking_evidence");
        item.put("score_explanation", match.explanation);
        return item;
    }

    private static double maskedRatio(byte[] mask) {
        if (mask.length == 0) return 0.0;
        int masked = 0;
        for (byte b : mask) if (b == 0) masked++;
        return masked / (double) mask.length;
    }

    private static String bytesToHex(byte[] bytes, byte[] mask) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 4 == 0) hex.append(" ");
            if (mask[i] == 0) hex.append("??");
            else hex.append(String.format("%02x", bytes[i] & 0xFF));
        }
        return hex.toString();
    }

    private static String maskToHex(byte[] mask) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < mask.length; i++) {
            if (i > 0 && i % 4 == 0) hex.append(" ");
            hex.append(String.format("%02x", mask[i] & 0xFF));
        }
        return hex.toString();
    }

    private static final class MaskPlan {
        final byte[] mask;
        final String comparisonMode;
        final String comparisonNote;
        final String error;

        MaskPlan(byte[] mask, String comparisonMode, String comparisonNote, String error) {
            this.mask = mask;
            this.comparisonMode = comparisonMode;
            this.comparisonNote = comparisonNote;
            this.error = error;
        }

        static MaskPlan error(String message) {
            return new MaskPlan(null, null, null, message);
        }
    }

    private static final class ScanOutcome {
        final List<MatchResult> matches = new ArrayList<>();
        boolean moreExist;
        boolean cancelled;
        boolean finishedAllRanges;
        int blocksScanned;
    }

    private static final class Score {
        final double value;
        final String explanation;
        Score(double value, String explanation) {
            this.value = value;
            this.explanation = explanation;
        }
    }

    private static final class MatchResult {
        final Address address;
        final Function containing;
        final Function atEntry;
        final double rankingScore;
        final String explanation;

        MatchResult(Address address, Function containing, Function atEntry, double rankingScore, String explanation) {
            this.address = address;
            this.containing = containing;
            this.atEntry = atEntry;
            this.rankingScore = rankingScore;
            this.explanation = explanation;
        }
    }
}
