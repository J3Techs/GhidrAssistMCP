/*
 *
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that retrieves a hexdump of memory at a specific address.
 * Displays data in standard hex+ASCII format.
 */
public class GetHexdumpTool implements McpTool {

    private static final int BYTES_PER_LINE = 16;

    @Override
    public String getName() {
        return "get_data_at";
    }

    @Override
    public String getDescription() {
        return "Get a hexdump of memory at a specific address in standard hex+ASCII format. " +
               "Useful for examining data structures, .rodata, .data, .bss, and other non-code regions.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.of(
                "address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "len", Map.of("type", "integer", "minimum", 1, "maximum", 65536)
            ),
            List.of("address", "len"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("No program currently loaded")
                .build();
        }

        // Get and validate address parameter
        String addressStr = arguments.get("address") instanceof String value ? value : null;
        if (addressStr == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("address parameter is required")
                .build();
        }

        final int length;
        try {
            if (!arguments.containsKey("len")) return ProjectToolSupport.error("len parameter is required");
            length = QueryPageBounds.integer(arguments, "len", 1, 1, 65536);
        } catch (IllegalArgumentException e) { return ProjectToolSupport.error(e.getMessage()); }

        // Parse the address
        Address address;
        try {
            address = currentProgram.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return McpSchema.CallToolResult.builder()
                    .isError(true).addTextContent("Invalid address format: " + addressStr)
                    .build();
            }
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .isError(true).addTextContent("Invalid address format: " + addressStr + " - " + e.getMessage())
                .build();
        }

        // Generate the hexdump
        try {
            address.addNoWrap(length - 1L);
            String hexdump = generateHexdump(currentProgram, address, length);
            return McpSchema.CallToolResult.builder()
                .isError(false)
                .addTextContent(hexdump)
                .build();
        } catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Error generating hexdump: " + e.getMessage())
                .build();
        }
    }

    /**
     * Generate a hexdump in standard format with hex and ASCII representation.
     * Format: ADDRESS  HEX_BYTES (16 per line, grouped by 8)  |ASCII|
     */
    private String generateHexdump(Program program, Address startAddr, int length) throws ghidra.program.model.address.AddressOverflowException {
        BoundedQueryText result = new BoundedQueryText(BoundedQueryText.PAGE_CHARS - 1024);
        Memory memory = program.getMemory();

        result.append("Hexdump at ").append(startAddr).append(" (").append(length).append(" bytes):\n\n");

        int bytesRead = 0;
        int unreadable = 0;
        int completeBytes = 0;

        while (bytesRead < length) {
            // Calculate how many bytes to read on this line
            int bytesToRead = Math.min(BYTES_PER_LINE, length - bytesRead);
            byte[] lineBytes = new byte[bytesToRead];
            boolean[] readable = new boolean[bytesToRead];

            // Read the bytes for this line
            int actualBytesRead = 0;
            for (int i = 0; i < bytesToRead; i++) {
                try {
                    lineBytes[i] = memory.getByte(startAddr.addNoWrap(bytesRead + i));
                    readable[i] = true;
                    actualBytesRead++;
                } catch (MemoryAccessException e) {
                    // If we can't read a byte, mark it as unreadable
                    unreadable++;
                    actualBytesRead++;
                }
            }

            // Format the line
            result.append(formatHexdumpLine(startAddr.addNoWrap(bytesRead), lineBytes, readable, actualBytesRead));
            result.append("\n");

            bytesRead += actualBytesRead;
            if (result.full()) break;
            completeBytes = bytesRead;
        }

        String footer = "\nUnreadable bytes: " + unreadable + " (among inspected bytes; ?? in hex, ? in ASCII).\n"
            + "Complete bytes displayed: " + completeBytes + "; output_truncated=" + result.full() + ".\n";
        if (completeBytes < length) footer += "Continue at address " + startAddr.addNoWrap(completeBytes)
            + " with len=" + (length - completeBytes) + " (repeats any partial line).\n";
        return result.toString() + footer;
    }

    /**
     * Format a single line of the hexdump.
     */
    private String formatHexdumpLine(Address lineAddr, byte[] bytes, boolean[] readable, int validBytes) {
        StringBuilder line = new StringBuilder();

        if ( lineAddr.getOffset() > (1L << 32)) {
	        // Address (8 hex digits)
	        line.append(String.format("%08x  ", lineAddr.getOffset()));
        } else {
            // Address (4 hex digits)
            line.append(String.format("%04x  ", lineAddr.getOffset()));
        }

        // Hex bytes (16 per line, with space after 8th byte)
        for (int i = 0; i < BYTES_PER_LINE; i++) {
            if (i < validBytes) {
                line.append(readable[i] ? String.format("%02x ", bytes[i] & 0xFF) : "?? ");
            } else {
                line.append("   "); // 3 spaces for missing bytes
            }

            // Extra space after 8th byte
            if (i == 7) {
                line.append(" ");
            }
        }

        // ASCII representation
        line.append(" |");
        for (int i = 0; i < validBytes; i++) {
            if (!readable[i]) { line.append('?'); continue; }
            char c = (char) (bytes[i] & 0xFF);
            // Print printable ASCII characters, otherwise use '.'
            if (c >= 32 && c <= 126) {
                line.append(c);
            } else {
                line.append('.');
            }
        }
        line.append("|");

        return line.toString();
    }
}
