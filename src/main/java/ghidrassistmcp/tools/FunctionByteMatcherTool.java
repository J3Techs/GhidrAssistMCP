/*
 * MCP tool that matches functions between binaries using byte patterns.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Matches functions between two open programs using byte patterns.
 * Takes entry bytes from a source function, optionally masks relocatable operands,
 * and searches for matches in the target program. Reports candidate matches with
 * confidence scores based on byte similarity and function size.
 */
public class FunctionByteMatcherTool implements McpTool {

    @Override
    public String getName() {
        return "function_byte_matcher";
    }

    @Override
    public String getDescription() {
        return "Match a function from one program to another by byte pattern. " +
               "Provide a source function name and source/target program names. " +
               "Extracts entry bytes from the source, masks branch/call target operands with wildcards, " +
               "and searches the target for matches. Returns candidates with confidence scores.";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "source_function", Map.of("type", "string", "description", "Function name or address in the source program"),
                "source_program", Map.of("type", "string", "description", "Name of the source program (with known symbols)"),
                "target_program", Map.of("type", "string", "description", "Name of the target program to search in"),
                "match_bytes", Map.of("type", "integer", "description", "Number of entry bytes to use for matching (default 24)", "default", 24),
                "mask_mode", Map.of("type", "string", "description",
                    "How to handle relocatable operands: 'auto' masks every 4th byte group in branch/call instructions, " +
                    "'none' uses raw bytes, 'aggressive' masks more liberally. Default: auto",
                    "default", "auto")
            ),
            List.of("source_function", "source_program", "target_program"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return McpSchema.CallToolResult.builder()
            .addTextContent("This tool requires backend context for multi-program access.")
            .build();
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (backend == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Backend context not available")
                .build();
        }

        String sourceFuncId = (String) arguments.get("source_function");
        String sourceProgramName = (String) arguments.get("source_program");
        String targetProgramName = (String) arguments.get("target_program");
        int matchBytes = 24;
        String maskMode = "auto";

        if (arguments.get("match_bytes") instanceof Number)
            matchBytes = ((Number) arguments.get("match_bytes")).intValue();
        if (arguments.get("mask_mode") instanceof String)
            maskMode = (String) arguments.get("mask_mode");

        // Resolve programs
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

        // Find source function
        Function sourceFunc = findFunction(sourceProgram, sourceFuncId);
        if (sourceFunc == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Function not found in source program: " + sourceFuncId)
                .build();
        }

        long sourceFuncSize = sourceFunc.getBody().getNumAddresses();
        int bytesToRead = Math.min(matchBytes, (int) sourceFuncSize);

        // Read source function entry bytes
        Memory sourceMem = sourceProgram.getMemory();
        byte[] sourceBytes = new byte[bytesToRead];
        byte[] mask = new byte[bytesToRead];

        try {
            Address entry = sourceFunc.getEntryPoint();
            for (int i = 0; i < bytesToRead; i++) {
                sourceBytes[i] = sourceMem.getByte(entry.add(i));
                mask[i] = (byte) 0xFF;
            }
        } catch (MemoryAccessException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Failed to read source function bytes: " + e.getMessage())
                .build();
        }

        // Apply masking based on mode
        if ("auto".equals(maskMode) || "aggressive".equals(maskMode)) {
            applyMask(sourceBytes, mask, maskMode, sourceProgram, sourceFunc);
        }

        // Search target program
        Memory targetMem = targetProgram.getMemory();
        List<MatchResult> matches = new ArrayList<>();

        try {
            Address startAddr = targetMem.getMinAddress();
            Address endAddr = targetMem.getMaxAddress();
            Address addr = startAddr;

            while (addr != null && matches.size() < 20) {
                addr = targetMem.findBytes(addr, endAddr, sourceBytes, mask, true, null);
                if (addr != null) {
                    Function targetFunc = targetProgram.getFunctionManager().getFunctionContaining(addr);
                    // Only count matches at function entry points or within executable memory
                    Function atEntry = targetProgram.getFunctionManager().getFunctionAt(addr);

                    double confidence = calculateConfidence(
                        sourceBytes, mask, sourceFuncSize,
                        targetMem, addr, targetFunc, atEntry);

                    matches.add(new MatchResult(addr,
                        atEntry != null ? atEntry.getName() : (targetFunc != null ? targetFunc.getName() + " (offset+" + addr.subtract(targetFunc.getEntryPoint()) + ")" : "no function"),
                        atEntry != null ? atEntry.getBody().getNumAddresses() : -1,
                        confidence));

                    addr = addr.add(1);
                }
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error during search: " + e.getMessage())
                .build();
        }

        // Sort by confidence descending
        matches.sort((a, b) -> Double.compare(b.confidence, a.confidence));

        // Format results
        StringBuilder result = new StringBuilder();
        result.append("Function Byte Match Results\n");
        result.append("==========================\n");
        result.append("Source: ").append(sourceFunc.getName()).append(" @ ").append(sourceFunc.getEntryPoint());
        result.append(" (").append(sourceFuncSize).append(" bytes)\n");
        result.append("Pattern: ").append(bytesToHex(sourceBytes, mask)).append("\n");
        result.append("Mask mode: ").append(maskMode).append("\n\n");

        if (matches.isEmpty()) {
            result.append("No matches found in ").append(targetProgramName);
        } else {
            result.append("Found ").append(matches.size()).append(" candidate(s):\n\n");
            for (int i = 0; i < matches.size(); i++) {
                MatchResult m = matches.get(i);
                result.append(String.format("  %d. %s @ %s", i + 1, m.funcName, m.address));
                if (m.funcSize > 0) {
                    result.append(String.format(" (%d bytes, size delta: %+d)",
                        m.funcSize, m.funcSize - sourceFuncSize));
                }
                result.append(String.format(" [confidence: %.0f%%]", m.confidence * 100));
                result.append("\n");
            }
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Apply masking to relocatable operands in PowerPC VLE instructions.
     * For 32-bit branch instructions (e_b, e_bl, etc.), mask the offset operand.
     */
    private void applyMask(byte[] bytes, byte[] mask, String mode, Program program, Function func) {
        // For PowerPC VLE, common relocatable patterns:
        // e_bl (branch and link): opcode in first 2 bytes, offset in remaining
        // e_lis / e_lwz with absolute addresses
        // In aggressive mode, mask bytes 2-3 of every 4-byte group (common operand position)

        if ("aggressive".equals(mode)) {
            // Mask the operand portion of each 4-byte instruction word
            for (int i = 0; i + 3 < bytes.length; i += 4) {
                // Keep opcode (high bits), mask low operand bits
                // For VLE, many instructions have operands in the lower 16 bits
                mask[i + 2] = 0;
                mask[i + 3] = 0;
            }
        } else {
            // Auto mode: selectively mask branch targets and load immediates
            for (int i = 0; i + 3 < bytes.length; i += 2) {
                int hw = ((bytes[i] & 0xFF) << 8) | (bytes[i + 1] & 0xFF);

                // Check for 32-bit VLE instructions (bit 0-4 patterns)
                // e_bl, e_b: starts with 0x78xx or 0x79xx (branch)
                // e_lis: 0x70xx (load immediate shifted)
                // se_ prefixed instructions are 16-bit, skip those
                int majorOp = (hw >> 10) & 0x3F;

                if (i + 3 < bytes.length) {
                    // 32-bit instruction check: if high byte indicates 32-bit form
                    boolean is32bit = (bytes[i] & 0x10) != 0 || majorOp >= 0x18;
                    if (is32bit) {
                        // Mask the displacement/immediate in bytes 2-3
                        if (i + 2 < mask.length) mask[i + 2] = 0;
                        if (i + 3 < mask.length) mask[i + 3] = 0;
                        i += 2; // skip to next instruction (already +2 from loop)
                    }
                }
            }
        }
    }

    private double calculateConfidence(byte[] sourceBytes, byte[] mask, long sourceFuncSize,
                                        Memory targetMem, Address matchAddr,
                                        Function containingFunc, Function atEntry) {
        double confidence = 0.5; // base for any byte match

        // Bonus if match is at a function entry point
        if (atEntry != null) {
            confidence += 0.25;

            // Bonus if function sizes are similar
            long targetSize = atEntry.getBody().getNumAddresses();
            double sizeRatio = Math.min(sourceFuncSize, targetSize) /
                              (double) Math.max(sourceFuncSize, targetSize);
            confidence += sizeRatio * 0.2;

            // Small penalty for large size differences
            if (sizeRatio < 0.5) confidence -= 0.1;
        }

        // Count non-masked bytes that matched (all of them matched, but more non-masked = better)
        int totalBytes = 0;
        int maskedBytes = 0;
        for (int i = 0; i < mask.length; i++) {
            totalBytes++;
            if (mask[i] == 0) maskedBytes++;
        }
        double specificityRatio = (totalBytes - maskedBytes) / (double) totalBytes;
        confidence += specificityRatio * 0.05;

        return Math.min(confidence, 1.0);
    }

    private Program findProgram(GhidrAssistMCPBackend backend, String name) {
        for (Program p : backend.getAllOpenPrograms()) {
            if (p.getName().equals(name)) return p;
        }
        return null;
    }

    private Function findFunction(Program program, String identifier) {
        // Try by name first
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(identifier)) return f;
        }
        // Try by address
        try {
            Address addr = program.getAddressFactory().getAddress(identifier);
            if (addr != null) {
                return program.getFunctionManager().getFunctionAt(addr);
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    private String bytesToHex(byte[] bytes, byte[] mask) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0 && i % 4 == 0) hex.append(" ");
            if (mask[i] == 0) {
                hex.append("??");
            } else {
                hex.append(String.format("%02x", bytes[i] & 0xFF));
            }
        }
        return hex.toString();
    }

    private static class MatchResult {
        Address address;
        String funcName;
        long funcSize;
        double confidence;

        MatchResult(Address address, String funcName, long funcSize, double confidence) {
            this.address = address;
            this.funcName = funcName;
            this.funcSize = funcSize;
            this.confidence = confidence;
        }
    }
}
