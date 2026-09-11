/*
 * WriteBytesTool - Write raw bytes to memory at specified address
 */
package ghidrassistmcp.tools;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that writes raw bytes to memory at a specified address.
 * Supports dry_run mode to validate without writing.
 */
public class WriteBytesTool implements McpTool {
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isDestructive() { return true; }

    @Override
    public String getName() {
        return "write_bytes";
    }

    @Override
    public String getDescription() {
        return "Write raw bytes to memory at a specified address. " +
               "Use dry_run=true to validate the operation without making changes.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "data_hex", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "dry_run", new McpSchema.JsonSchema("boolean", null, null, null, null, null)
            ),
            List.of("address", "data_hex"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        // Get parameters
        String addressStr = (String) arguments.get("address");
        String dataHex = (String) arguments.get("data_hex");
        Boolean dryRun = (Boolean) arguments.get("dry_run");

        if (addressStr == null || dataHex == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("address and data_hex parameters are required")
                .build();
        }

        if (dryRun == null) {
            dryRun = false;
        }

        // Parse hex string to bytes
        byte[] bytes;
        try {
            bytes = parseHexString(dataHex);
        } catch (IllegalArgumentException e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid hex string: " + e.getMessage())
                .build();
        }

        if (bytes.length == 0) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No bytes to write (empty data_hex)")
                .build();
        }

        // Limit maximum write size
        if (bytes.length > 1048576) { // 1 MB max
            return McpSchema.CallToolResult.builder()
                .addTextContent("Write size exceeds maximum allowed value of 1048576 bytes (1 MB)")
                .build();
        }

        // Parse the address
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

        // Validate memory range
        Memory memory = currentProgram.getMemory();
        MemoryBlock block = memory.getBlock(address);
        if (block == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Address " + addressStr + " is not in mapped memory")
                .build();
        }

        // Check end address is also valid
        Address endAddress = address.add(bytes.length - 1);
        MemoryBlock endBlock = memory.getBlock(endAddress);
        if (endBlock == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Write range exceeds mapped memory (end address: " + endAddress + ")")
                .build();
        }

        // Calculate SHA256 hash
        String sha256 = calculateSHA256(bytes);

        // If dry run, just report what would happen
        if (dryRun) {
            StringBuilder result = new StringBuilder();
            result.append("DRY RUN - Write Bytes Validation:\n\n");
            result.append("Address: ").append(addressStr).append("\n");
            result.append("Bytes to write: ").append(bytes.length).append("\n");
            result.append("End address: ").append(endAddress).append("\n");
            result.append("Memory block: ").append(block.getName()).append("\n");
            result.append("Block permissions: ").append(getPermissions(block)).append("\n");
            result.append("SHA256: ").append(sha256).append("\n\n");
            result.append("Status: VALID - would write successfully");
            return McpSchema.CallToolResult.builder()
                .addTextContent(result.toString())
                .build();
        }

        // Perform the write within a transaction
        int transactionID = currentProgram.startTransaction("Write Bytes");
        try {
            memory.setBytes(address, bytes);
            currentProgram.endTransaction(transactionID, true);

            StringBuilder result = new StringBuilder();
            result.append("Write Bytes Result:\n\n");
            result.append("Address: ").append(addressStr).append("\n");
            result.append("Bytes written: ").append(bytes.length).append("\n");
            result.append("End address: ").append(endAddress).append("\n");
            result.append("SHA256: ").append(sha256).append("\n\n");
            result.append("Status: SUCCESS");
            return McpSchema.CallToolResult.builder()
                .addTextContent(result.toString())
                .build();

        } catch (MemoryAccessException e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Memory access error: " + e.getMessage())
                .build();
        } catch (Exception e) {
            currentProgram.endTransaction(transactionID, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error writing bytes: " + e.getMessage())
                .build();
        }
    }

    /**
     * Parse a hex string into bytes. Supports 0x prefix and whitespace.
     */
    private byte[] parseHexString(String hex) throws IllegalArgumentException {
        // Remove 0x prefix if present
        if (hex.toLowerCase().startsWith("0x")) {
            hex = hex.substring(2);
        }

        // Remove all whitespace
        hex = hex.replaceAll("\\s+", "");

        // Validate even length
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have an even number of characters");
        }

        // Validate hex characters
        if (!hex.matches("[0-9a-fA-F]*")) {
            throw new IllegalArgumentException("Hex string contains invalid characters");
        }

        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    /**
     * Calculate SHA256 hash of data.
     */
    private String calculateSHA256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "hash_error";
        }
    }

    /**
     * Get permission string for a memory block.
     */
    private String getPermissions(MemoryBlock block) {
        StringBuilder sb = new StringBuilder();
        sb.append(block.isRead() ? "r" : "-");
        sb.append(block.isWrite() ? "w" : "-");
        sb.append(block.isExecute() ? "x" : "-");
        return sb.toString();
    }
}
