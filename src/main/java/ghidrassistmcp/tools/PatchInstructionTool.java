/*
 * PatchInstructionTool - Assemble and patch instructions at a specified address
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPPlugin;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that patches instructions at a specified address.
 * Emulates Ghidra's Ctrl+Shift+G patch instruction functionality.
 * Can show current instruction or assemble and patch new instructions.
 */
public class PatchInstructionTool implements McpTool {

    @Override
    public String getName() {
        return "patch_instruction";
    }

    @Override
    public String getDescription() {
        return "Patch instructions at a specified address (like Ctrl+Shift+G in Ghidra). " +
               "Without 'instruction' parameter: shows current instruction at address. " +
               "With 'instruction' parameter: assembles and patches the instruction. " +
               "Supports multi-line assembly separated by newlines or semicolons.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "instruction", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "dry_run", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of(), null, null, null); // address is optional (uses cursor), instruction is optional (shows current)
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // Fallback when backend not available
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String addressStr = (String) arguments.get("address");
        if (addressStr == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Address required when backend context unavailable (no cursor access)")
                .build();
        }

        return executeWithAddress(arguments, currentProgram, addressStr);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String addressStr = (String) arguments.get("address");

        // If no address provided, try to use cursor position
        if (addressStr == null || addressStr.trim().isEmpty()) {
            GhidrAssistMCPPlugin plugin = backend.getActivePlugin();
            if (plugin != null) {
                Address cursorAddr = plugin.getCurrentAddress();
                if (cursorAddr != null) {
                    addressStr = cursorAddr.toString();
                }
            }
        }

        if (addressStr == null || addressStr.trim().isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No address specified and cursor position not available. " +
                              "Please provide an 'address' parameter.")
                .build();
        }

        return executeWithAddress(arguments, currentProgram, addressStr);
    }

    private McpSchema.CallToolResult executeWithAddress(Map<String, Object> arguments,
            Program currentProgram, String addressStr) {

        String instruction = (String) arguments.get("instruction");
        Boolean dryRun = (Boolean) arguments.get("dry_run");
        if (dryRun == null) dryRun = false;

        // Parse address
        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid address format: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid address format: " + addressStr + " - " + e.getMessage())
                .build();
        }

        // If no instruction provided, show current instruction at address
        if (instruction == null || instruction.trim().isEmpty()) {
            return showCurrentInstruction(currentProgram, address);
        }

        // Assemble and patch the instruction
        return patchInstruction(currentProgram, address, instruction, dryRun);
    }

    /**
     * Show the current instruction at the given address.
     */
    private McpSchema.CallToolResult showCurrentInstruction(Program program, Address address) {
        Listing listing = program.getListing();
        Instruction instr = listing.getInstructionAt(address);

        StringBuilder result = new StringBuilder();
        result.append("Instruction at ").append(address).append(":\n\n");

        if (instr == null) {
            // Check if it's in the middle of an instruction
            Instruction containing = listing.getInstructionContaining(address);
            if (containing != null) {
                result.append("Address is inside an instruction:\n");
                result.append("  ").append(containing.getAddress()).append(": ");
                result.append(containing.toString()).append("\n");
                try {
                    result.append("  Bytes: ").append(bytesToHex(containing.getBytes())).append("\n");
                } catch (Exception e) {
                    result.append("  Bytes: (unable to read)\n");
                }
                result.append("  Length: ").append(containing.getLength()).append(" bytes\n");
            } else {
                // Check if it's data
                if (listing.getDataAt(address) != null) {
                    result.append("No instruction at address (defined data present)\n");
                } else {
                    result.append("No instruction at address (undefined or data region)\n");
                }

                // Show raw bytes
                try {
                    Memory memory = program.getMemory();
                    byte[] bytes = new byte[16];
                    int read = memory.getBytes(address, bytes);
                    if (read > 0) {
                        result.append("\nRaw bytes: ");
                        for (int i = 0; i < Math.min(read, 8); i++) {
                            result.append(String.format("%02x ", bytes[i] & 0xff));
                        }
                        result.append("\n");
                    }
                } catch (Exception e) {
                    // Ignore memory read errors
                }
            }
            return McpSchema.CallToolResult.builder()
                .addTextContent(result.toString())
                .build();
        }

        // Show instruction details
        result.append("  Mnemonic: ").append(instr.getMnemonicString()).append("\n");
        result.append("  Full: ").append(instr.toString()).append("\n");
        try {
            result.append("  Bytes: ").append(bytesToHex(instr.getBytes())).append("\n");
        } catch (Exception e) {
            result.append("  Bytes: (unable to read)\n");
        }
        result.append("  Length: ").append(instr.getLength()).append(" bytes\n");

        // Show next few instructions for context
        result.append("\nContext (next instructions):\n");
        Address nextAddr = instr.getAddress();
        int count = 0;
        while (nextAddr != null && count < 5) {
            Instruction next = listing.getInstructionAt(nextAddr);
            if (next == null) break;

            String prefix = count == 0 ? ">> " : "   ";
            result.append(prefix).append(next.getAddress()).append(": ");
            result.append(next.toString()).append("\n");

            nextAddr = next.getNext() != null ? next.getNext().getAddress() : null;
            count++;
        }

        result.append("\nTo patch, call again with 'instruction' parameter.");

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Assemble and patch instruction at the given address.
     */
    private McpSchema.CallToolResult patchInstruction(Program program, Address address,
            String instruction, boolean dryRun) {

        // Split instruction(s) by newlines or semicolons
        String[] lines = instruction.split("[;\n]+");
        for (int i = 0; i < lines.length; i++) {
            lines[i] = lines[i].trim();
        }

        // Filter empty lines
        java.util.List<String> validLines = new java.util.ArrayList<>();
        for (String line : lines) {
            if (!line.isEmpty()) {
                validLines.add(line);
            }
        }

        if (validLines.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No valid instruction provided")
                .build();
        }

        StringBuilder result = new StringBuilder();
        result.append("Patch Instruction");
        if (dryRun) {
            result.append(" (DRY RUN)");
        }
        result.append("\n");
        result.append("=================\n\n");
        result.append("Address: ").append(address).append("\n");
        result.append("Language: ").append(program.getLanguageID()).append("\n\n");

        // Show original instruction(s)
        Listing listing = program.getListing();
        Instruction origInstr = listing.getInstructionAt(address);
        if (origInstr != null) {
            result.append("Original:\n");
            result.append("  ").append(origInstr.toString()).append("\n");
            try {
                result.append("  Bytes: ").append(bytesToHex(origInstr.getBytes())).append("\n\n");
            } catch (Exception e) {
                result.append("  Bytes: (unable to read)\n\n");
            }
        }

        result.append("New instruction(s):\n");
        for (String line : validLines) {
            result.append("  ").append(line).append("\n");
        }
        result.append("\n");

        if (dryRun) {
            // Just try to assemble without writing
            try {
                Assembler asm = Assemblers.getAssembler(program);
                Address currentAddr = address;

                for (String line : validLines) {
                    byte[] bytes = asm.assembleLine(currentAddr, line);
                    result.append("Would assemble '").append(line).append("': ");
                    result.append(bytesToHex(bytes)).append(" (").append(bytes.length).append(" bytes)\n");
                    currentAddr = currentAddr.add(bytes.length);
                }

                result.append("\nStatus: DRY RUN SUCCESS - Assembly valid, no changes made");

            } catch (Exception e) {
                result.append("Assembly error: ").append(e.getMessage()).append("\n");
                result.append("\nStatus: DRY RUN FAILED - Assembly invalid");
                Msg.warn(this, "Assembly dry-run failed: " + e.getMessage());
            }

            return McpSchema.CallToolResult.builder()
                .addTextContent(result.toString())
                .build();
        }

        // Perform actual patch within transaction
        int transactionID = program.startTransaction("Patch Instruction");
        try {
            Assembler asm = Assemblers.getAssembler(program);

            // Assemble each line
            String[] lineArray = validLines.toArray(new String[0]);
            InstructionIterator it = asm.assemble(address, lineArray);

            // Count assembled instructions and show results
            int count = 0;
            Address lastAddr = address;
            while (it.hasNext()) {
                Instruction newInstr = it.next();
                result.append("Assembled: ").append(newInstr.getAddress()).append(": ");
                result.append(newInstr.toString()).append(" [");
                result.append(bytesToHex(newInstr.getBytes())).append("]\n");
                lastAddr = newInstr.getAddress().add(newInstr.getLength());
                count++;
            }

            program.endTransaction(transactionID, true);

            result.append("\nTotal: ").append(count).append(" instruction(s) patched\n");
            result.append("End address: ").append(lastAddr).append("\n");
            result.append("\nStatus: SUCCESS");

        } catch (Exception e) {
            program.endTransaction(transactionID, false);

            result.append("Assembly/patch error: ").append(e.getMessage()).append("\n");

            // Provide helpful error info
            if (e.getMessage() != null && e.getMessage().contains("syntax")) {
                result.append("\nHint: Check instruction syntax for this architecture.\n");
                result.append("Language: ").append(program.getLanguageID()).append("\n");
            }

            result.append("\nStatus: FAILED");
            Msg.error(this, "Patch instruction failed", e);
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent(result.toString())
            .build();
    }

    /**
     * Convert byte array to hex string.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x ", b & 0xff));
        }
        return sb.toString().trim();
    }
}
