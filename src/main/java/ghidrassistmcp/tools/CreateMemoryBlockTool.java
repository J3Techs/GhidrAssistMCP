package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that creates a new memory block in the current program.
 * Useful for mapping runtime RAM regions so data types/structs can be applied.
 */
public class CreateMemoryBlockTool implements McpTool {

    @Override
    public String getName() {
        return "create_memory_block";
    }

    @Override
    public String getDescription() {
        return "Create a memory block at a specified address range. " +
               "Supports initialized/uninitialized blocks, permissions, overlay mode, and dry_run.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("name", new McpSchema.JsonSchema("string", null, null, null, null, null)),
                Map.entry("start", new McpSchema.JsonSchema("string", null, null, null, null, null)),
                Map.entry("length", new McpSchema.JsonSchema("integer", null, null, null, null, null)),
                Map.entry("end", new McpSchema.JsonSchema("string", null, null, null, null, null)),
                Map.entry("initialized", new McpSchema.JsonSchema("boolean", null, null, null, null, null)),
                Map.entry("initial_value", new McpSchema.JsonSchema("integer", null, null, null, null, null)),
                Map.entry("overlay", new McpSchema.JsonSchema("boolean", null, null, null, null, null)),
                Map.entry("read", new McpSchema.JsonSchema("boolean", null, null, null, null, null)),
                Map.entry("write", new McpSchema.JsonSchema("boolean", null, null, null, null, null)),
                Map.entry("execute", new McpSchema.JsonSchema("boolean", null, null, null, null, null)),
                Map.entry("dry_run", new McpSchema.JsonSchema("boolean", null, null, null, null, null))
            ),
            List.of("name", "start"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        String name = asString(arguments.get("name"));
        String startStr = asString(arguments.get("start"));
        String endStr = asString(arguments.get("end"));

        if (name == null || name.isBlank() || startStr == null || startStr.isBlank()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("name and start parameters are required")
                .build();
        }

        boolean initialized = getBoolean(arguments, "initialized", false);
        int initialValue = getInt(arguments, "initial_value", 0);
        boolean overlay = getBoolean(arguments, "overlay", false);
        boolean readPerm = getBoolean(arguments, "read", true);
        boolean writePerm = getBoolean(arguments, "write", true);
        boolean execPerm = getBoolean(arguments, "execute", false);
        boolean dryRun = getBoolean(arguments, "dry_run", false);

        Address start = parseAddress(currentProgram, startStr);
        if (start == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid start address: " + startStr)
                .build();
        }

        long length = getLong(arguments, "length", -1L);
        if (length <= 0) {
            if (endStr == null || endStr.isBlank()) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Either length (>0) or end must be provided")
                    .build();
            }
            Address endAddr = parseAddress(currentProgram, endStr);
            if (endAddr == null) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Invalid end address: " + endStr)
                    .build();
            }
            try {
                long delta = endAddr.subtract(start);
                length = delta + 1;
            }
            catch (Exception e) {
                return McpSchema.CallToolResult.builder()
                    .addTextContent("Could not compute length from start/end: " + e.getMessage())
                    .build();
            }
        }

        if (length <= 0) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Block length must be > 0")
                .build();
        }
        if (length > 0x40000000L) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Block length too large (max 0x40000000)")
                .build();
        }

        Address end;
        try {
            end = start.addNoWrap(length - 1);
        }
        catch (Exception e) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Invalid block range: " + e.getMessage())
                .build();
        }

        Memory memory = currentProgram.getMemory();
        if (!overlay) {
            for (MemoryBlock block : memory.getBlocks()) {
                if (rangesOverlap(start, end, block.getStart(), block.getEnd())) {
                    return McpSchema.CallToolResult.builder()
                        .addTextContent("Range overlaps existing block '" + block.getName() +
                            "' at " + block.getStart() + "-" + block.getEnd() +
                            ". Use overlay=true if intentional.")
                        .build();
                }
            }
        }

        if (dryRun) {
            StringBuilder sb = new StringBuilder();
            sb.append("DRY RUN - Create Memory Block\n\n");
            sb.append("Name: ").append(name).append("\n");
            sb.append("Start: ").append(start).append("\n");
            sb.append("End: ").append(end).append("\n");
            sb.append("Length: ").append(length).append(" (0x").append(Long.toHexString(length)).append(")\n");
            sb.append("Type: ").append(initialized ? "initialized" : "uninitialized").append("\n");
            if (initialized) {
                sb.append("Initial value: 0x").append(Integer.toHexString(initialValue & 0xff)).append("\n");
            }
            sb.append("Overlay: ").append(overlay).append("\n");
            sb.append("Permissions: ")
              .append(readPerm ? "r" : "-")
              .append(writePerm ? "w" : "-")
              .append(execPerm ? "x" : "-")
              .append("\n");
            sb.append("Status: VALID");

            return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
        }

        int tx = currentProgram.startTransaction("Create Memory Block");
        try {
            MemoryBlock newBlock;
            if (initialized) {
                newBlock = memory.createInitializedBlock(
                    name, start, length, (byte) (initialValue & 0xff), TaskMonitor.DUMMY, overlay);
            }
            else {
                newBlock = memory.createUninitializedBlock(name, start, length, overlay);
            }

            newBlock.setRead(readPerm);
            newBlock.setWrite(writePerm);
            newBlock.setExecute(execPerm);

            currentProgram.endTransaction(tx, true);

            StringBuilder sb = new StringBuilder();
            sb.append("Successfully created memory block\n\n");
            sb.append("Name: ").append(newBlock.getName()).append("\n");
            sb.append("Range: ").append(newBlock.getStart()).append("-").append(newBlock.getEnd()).append("\n");
            sb.append("Length: ").append(newBlock.getSize()).append(" (0x")
              .append(Long.toHexString(newBlock.getSize())).append(")\n");
            sb.append("Permissions: ")
              .append(newBlock.isRead() ? "r" : "-")
              .append(newBlock.isWrite() ? "w" : "-")
              .append(newBlock.isExecute() ? "x" : "-");

            return McpSchema.CallToolResult.builder().addTextContent(sb.toString()).build();
        }
        catch (Exception e) {
            currentProgram.endTransaction(tx, false);
            return McpSchema.CallToolResult.builder()
                .addTextContent("Error creating memory block: " + e.getMessage())
                .build();
        }
    }

    private static boolean rangesOverlap(Address aStart, Address aEnd, Address bStart, Address bEnd) {
        return aStart.compareTo(bEnd) <= 0 && bStart.compareTo(aEnd) <= 0;
    }

    private static Address parseAddress(Program program, String s) {
        try {
            Address addr = program.getAddressFactory().getAddress(s);
            if (addr != null) {
                return addr;
            }
            if (s != null && !s.startsWith("0x") && !s.startsWith("0X")) {
                return program.getAddressFactory().getAddress("0x" + s);
            }
            return null;
        }
        catch (Exception e) {
            return null;
        }
    }

    private static String asString(Object o) {
        return o == null ? null : o.toString();
    }

    private static boolean getBoolean(Map<String, Object> args, String key, boolean defaultValue) {
        Object v = args.get(key);
        if (v == null) {
            return defaultValue;
        }
        if (v instanceof Boolean) {
            return ((Boolean) v).booleanValue();
        }
        if (v instanceof Number) {
            return ((Number) v).intValue() != 0;
        }
        return Boolean.parseBoolean(v.toString());
    }

    private static int getInt(Map<String, Object> args, String key, int defaultValue) {
        Object v = args.get(key);
        if (v == null) {
            return defaultValue;
        }
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        String s = v.toString().trim();
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                return (int) Long.parseLong(s.substring(2), 16);
            }
            return Integer.parseInt(s);
        }
        catch (Exception e) {
            return defaultValue;
        }
    }

    private static long getLong(Map<String, Object> args, String key, long defaultValue) {
        Object v = args.get(key);
        if (v == null) {
            return defaultValue;
        }
        if (v instanceof Number) {
            return ((Number) v).longValue();
        }
        String s = v.toString().trim();
        try {
            if (s.startsWith("0x") || s.startsWith("0X")) {
                return Long.parseLong(s.substring(2), 16);
            }
            return Long.parseLong(s);
        }
        catch (Exception e) {
            return defaultValue;
        }
    }
}

