/*
 * MCP tool for bulk region-based function label transfer between binaries.
 * Transfers all named function labels from a source program to a target program
 * for a given address range, with automatic offset detection and verification.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.HashMap;
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
import ghidra.util.task.ConsoleTaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
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
               "Use for bulk cross-binary label transfer between different OS revisions of the same firmware.";
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
                    "description", "Name of the source program (with known symbols)"),
                "target_program", Map.of("type", "string",
                    "description", "Name of the stripped target program to label"),
                "start_address", Map.of("type", "string",
                    "description", "Start of source address range (hex, e.g. \"0x00287200\")"),
                "end_address", Map.of("type", "string",
                    "description", "End of source address range (hex, e.g. \"0x002890FF\")"),
                "code_offset", Map.of("type", "integer",
                    "description", "Known offset (target = source + offset). If omitted, auto-detected."),
                "dry_run", Map.of("type", "boolean",
                    "description", "If true, report matches without applying labels (default false)",
                    "default", false),
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
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                             GhidrAssistMCPBackend backend) {
        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        // --- Parse arguments ---
        String sourceProgramName = (String) arguments.get("source_program");
        String targetProgramName = (String) arguments.get("target_program");
        String startAddrStr = (String) arguments.get("start_address");
        String endAddrStr = (String) arguments.get("end_address");

        boolean dryRun = false;
        if (arguments.get("dry_run") instanceof Boolean)
            dryRun = (Boolean) arguments.get("dry_run");

        boolean createFunctions = true;
        if (arguments.get("create_functions") instanceof Boolean)
            createFunctions = (Boolean) arguments.get("create_functions");

        double sizeTolerance = 0.2;
        if (arguments.get("size_tolerance") instanceof Number)
            sizeTolerance = ((Number) arguments.get("size_tolerance")).doubleValue();

        Long codeOffset = null;
        if (arguments.get("code_offset") instanceof Number)
            codeOffset = ((Number) arguments.get("code_offset")).longValue();

        // --- Resolve programs ---
        Program sourceProgram = findProgram(backend, sourceProgramName);
        Program targetProgram = findProgram(backend, targetProgramName);

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

        // ========== PHASE A: Offset Detection ==========
        long detectedOffset;
        int sampleCount;

        if (codeOffset != null) {
            detectedOffset = codeOffset;
            sampleCount = -1; // user-provided
        } else {
            OffsetResult offsetResult = detectOffset(sourceProgram, targetProgram, startAddr, endAddr);
            if (offsetResult.error != null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Offset detection failed: " + offsetResult.error)
                    .build();
            }
            detectedOffset = offsetResult.offset;
            sampleCount = offsetResult.agreementCount;
        }

        // ========== PHASE B: Verified Transfer ==========
        TransferResult transferResult = transferLabels(sourceProgram, targetProgram,
            startAddr, endAddr, detectedOffset, dryRun, createFunctions, sizeTolerance);

        // ========== PHASE C: Report ==========
        return buildReport(sourceProgramName, targetProgramName, startAddrStr, endAddrStr,
            detectedOffset, sampleCount, dryRun, createFunctions, sizeTolerance, transferResult);
    }

    // ==================== Phase A: Offset Detection ====================

    /**
     * Auto-detect the code offset between source and target by sampling functions
     * and byte-matching their opcode patterns.
     */
    private OffsetResult detectOffset(Program sourceProgram, Program targetProgram,
                                       Address startAddr, Address endAddr) {
        OffsetResult result = new OffsetResult();

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

            // Read opcode pattern: first 4 instruction words (16 bytes)
            // Mask: keep bytes 0,1 of each word (opcode), mask bytes 2,3 (operand)
            int patternLen = OFFSET_PATTERN_WORDS * 4;
            byte[] pattern = new byte[patternLen];
            byte[] mask = new byte[patternLen];

            try {
                for (int i = 0; i < patternLen; i++) {
                    pattern[i] = srcMem.getByte(srcEntry.add(i));
                    mask[i] = (i % 4 < 2) ? (byte) 0xFF : 0;
                }
            } catch (MemoryAccessException e) {
                sampleDetails.add(String.format("  SKIP %s: can't read source bytes", srcFunc.getName()));
                continue;
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
                Address matchAddr = tgtMem.findBytes(searchStart, searchEnd, pattern, mask, true, null);
                while (matchAddr != null && !foundMatch) {
                    // Check if this is a function entry point
                    Function tgtFunc = tgtFuncMgr.getFunctionAt(matchAddr);
                    if (tgtFunc != null) {
                        // Check size similarity (relaxed for offset detection)
                        long tgtSize = tgtFunc.getBody().getNumAddresses();
                        double sizeRatio = Math.min(srcSize, tgtSize) /
                                           (double) Math.max(srcSize, tgtSize);
                        if (sizeRatio > 0.5) {
                            long offset = matchAddr.getOffset() - srcOffset;
                            offsets.add(offset);
                            sampleDetails.add(String.format("  MATCH %s: src=0x%08x tgt=0x%08x offset=%+d (size %d vs %d)",
                                srcFunc.getName(), srcOffset, matchAddr.getOffset(), offset, srcSize, tgtSize));
                            foundMatch = true;
                        }
                    }
                    if (!foundMatch) {
                        matchAddr = tgtMem.findBytes(matchAddr.add(1), searchEnd, pattern, mask, true, null);
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
                                           double sizeTolerance) {
        TransferResult result = new TransferResult();

        Memory srcMem = sourceProgram.getMemory();
        Memory tgtMem = targetProgram.getMemory();
        AddressSpace tgtAddrSpace = targetProgram.getAddressFactory().getDefaultAddressSpace();
        FunctionManager tgtFuncMgr = targetProgram.getFunctionManager();
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        int txId = -1;
        if (!dryRun) {
            txId = targetProgram.startTransaction("Bulk Region Transfer");
        }

        try {
            int consecutiveMismatches = 0;

            FunctionIterator funcIter = sourceProgram.getFunctionManager().getFunctions(startAddr, true);
            while (funcIter.hasNext()) {
                Function srcFunc = funcIter.next();
                if (srcFunc.getEntryPoint().compareTo(endAddr) > 0) break;
                result.totalSourceFunctions++;

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
                long tgtOffset = srcOffset + offset;
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

                // Opcode verification
                int compareBytes = (int) Math.min(Math.min(srcSize, tgtSize), VERIFY_MAX_BYTES);
                compareBytes = (compareBytes / 4) * 4; // round down to word boundary
                if (compareBytes >= 4) {
                    double opcodeMatch = computeOpcodeMatch(srcMem, srcEntry, tgtMem, tgtAddr, compareBytes);
                    if (opcodeMatch < OPCODE_MATCH_THRESHOLD) {
                        result.addMismatch(srcName, srcEntry, String.format(
                            "opcode mismatch: %.0f%% match (threshold=%.0f%%), compared %d bytes",
                            opcodeMatch * 100, OPCODE_MATCH_THRESHOLD * 100, compareBytes));
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
                targetProgram.endTransaction(txId, true);
            }

        } catch (Exception e) {
            if (!dryRun && txId >= 0) {
                targetProgram.endTransaction(txId, false);
            }
            result.fatalError = "Transaction failed: " + e.getMessage();
        }

        return result;
    }

    /**
     * Compare opcode bytes (first 2 bytes of each 4-byte instruction word) between
     * source and target at the given addresses.
     */
    private double computeOpcodeMatch(Memory srcMem, Address srcAddr,
                                       Memory tgtMem, Address tgtAddr, int numBytes) {
        int matched = 0;
        int total = 0;

        for (int i = 0; i + 1 < numBytes; i += 4) {
            try {
                byte srcOp0 = srcMem.getByte(srcAddr.add(i));
                byte srcOp1 = srcMem.getByte(srcAddr.add(i + 1));
                byte tgtOp0 = tgtMem.getByte(tgtAddr.add(i));
                byte tgtOp1 = tgtMem.getByte(tgtAddr.add(i + 1));

                if (srcOp0 == tgtOp0 && srcOp1 == tgtOp1) matched++;
                total++;
            } catch (MemoryAccessException e) {
                // Stop comparing at memory boundary
                break;
            }
        }

        if (total == 0) return 0.0;
        return (double) matched / total;
    }

    /**
     * Create a function at the given address by disassembling first, then creating.
     */
    private Function createFunctionAt(Program program, Address addr, ConsoleTaskMonitor monitor) {
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
                                                   double sizeTolerance, TransferResult tr) {
        StringBuilder report = new StringBuilder();
        report.append("Bulk Region Transfer Report\n");
        report.append("===========================\n");
        report.append("Source: ").append(sourceName).append("\n");
        report.append("Target: ").append(targetName).append("\n");
        report.append("Range: ").append(startAddr).append(" — ").append(endAddr).append("\n");
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

        return McpSchema.CallToolResult.builder()
            .addTextContent(report.toString())
            .build();
    }

    // ==================== Helpers ====================

    private Program findProgram(GhidrAssistMCPBackend backend, String name) {
        for (Program p : backend.getAllOpenPrograms()) {
            if (p.getName().equals(name)) return p;
        }
        return null;
    }

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
        String fatalError = null;

        List<String> mismatches = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        List<String> details = new ArrayList<>();

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
