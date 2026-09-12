/*
 * MCP tool for searching byte patterns in memory.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.ProgramIdentity;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Bounded structured byte-pattern search over executable loaded initialized memory.
 * A result cap is not uniqueness. This is a fallback scanner, not a join/matcher tool.
 */
public class SearchBytesTool implements McpTool {

    private static final int DEFAULT_LIMIT = 100;

    @Override
    public String getName() {
        return "search_bytes";
    }

    @Override
    public String getDescription() {
        return "Search executable loaded initialized memory for a hex byte pattern with optional ?? wildcards. "
            + "Returns structured hits with function entry/interior/block position. "
            + "Default scan skips hash and pseudo spaces. A hit cap cannot establish uniqueness. "
            + "This is a bounded fallback, not a function-join tool.";
    }

    @Override
    public boolean isReadOnly() {
        return true;
    }

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public boolean isLongRunning() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("pattern", Map.of("type", "string", "minLength", 1,
            "description", "Hex bytes with optional ?? or ** wildcards (e.g. '48 8b c1' or '48??c1')"));
        properties.put("limit", Map.of("type", "integer", "minimum", 1, "maximum", QueryPageBounds.MAX_LIMIT,
            "default", DEFAULT_LIMIT,
            "description", "Maximum matches to return (default 100, maximum 1000). Hitting the cap does not imply uniqueness."));
        properties.put("program", Map.of("type", "string",
            "description", "Optional exact open program name, project path, URL, or program_id"));
        properties.put("program_name", Map.of("type", "string",
            "description", "Optional exact open program name, project path, URL, or program_id (alias of program)"));
        properties.put("program_id", Map.of("type", "string",
            "description", "Exact program_id returned by list_binaries or runtime diagnostics"));
        properties.put("start_address", Map.of("type", "string",
            "description", "Optional inclusive start of the scan range"));
        properties.put("end_address", Map.of("type", "string",
            "description", "Optional inclusive end of the scan range"));
        return new McpSchema.JsonSchema("object", properties, List.of("pattern"), null, null, null);
    }

    @Override
    public Map<String, Object> getOutputSchema() {
        Map<String, Object> functionRefProps = new LinkedHashMap<>();
        functionRefProps.put("name", Map.of("type", "string"));
        functionRefProps.put("entry", Map.of("type", "string"));
        functionRefProps.put("size", Map.of("type", "integer", "minimum", 0));
        Map<String, Object> functionRef = MatcherContracts.objectSchema(functionRefProps, List.of("name", "entry", "size"));
        Map<String, Object> hitProps = new LinkedHashMap<>();
        hitProps.put("address", Map.of("type", "string"));
        hitProps.put("space", Map.of("type", "string"));
        hitProps.put("block_name", Map.of("type", "string"));
        hitProps.put("containing_function", MatcherContracts.nullable(functionRef));
        hitProps.put("at_entry", Map.of("type", "boolean"));
        hitProps.put("position", Map.of("type", "string", "enum", List.of("entry", "interior", "block")));
        hitProps.put("program_id", Map.of("type", "string"));
        hitProps.put("modification_number", Map.of("type", "string"));
        Map<String, Object> hit = MatcherContracts.objectSchema(hitProps,
            List.of("address", "space", "block_name", "containing_function", "at_entry", "position",
                "program_id", "modification_number"));
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("program_id", Map.of("type", "string"));
        properties.put("program_name", Map.of("type", "string"));
        properties.put("modification_number", Map.of("type", "string"));
        properties.put("pattern", Map.of("type", "string"));
        properties.put("start_address", MatcherContracts.nullable(Map.of("type", "string")));
        properties.put("end_address", MatcherContracts.nullable(Map.of("type", "string")));
        properties.put("scan_scope", Map.of("type", "string"));
        properties.put("blocks_scanned", Map.of("type", "integer", "minimum", 0));
        properties.put("candidate_count", Map.of("type", "integer", "minimum", 0));
        properties.put("result_cap", Map.of("type", "integer", "minimum", 1));
        properties.put("scan_complete", Map.of("type", "boolean"));
        properties.put("scan_truncated", Map.of("type", "boolean"));
        properties.put("cancelled", Map.of("type", "boolean"));
        properties.put("unique", Map.of("type", "boolean",
            "description", "True only for a single complete unscapped hit; a cap never implies uniqueness"));
        properties.put("matches", Map.of("type", "array", "items", hit, "maxItems", QueryPageBounds.MAX_LIMIT));
        return MatcherContracts.objectSchema(properties, List.of(
            "program_id", "modification_number", "pattern", "candidate_count", "result_cap",
            "scan_complete", "scan_truncated", "cancelled", "unique", "matches"));
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend) {
        return execute(arguments, currentProgram, backend, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
            GhidrAssistMCPBackend backend, McpTask task) {
        ProgramSelection.Lease lease = null;
        try {
            String selector = programSelector(arguments);
            Program program = currentProgram;
            if (selector != null && backend != null) {
                lease = ProgramSelection.lease(backend, selector, currentProgram);
                program = lease.program();
            }
            if (program == null) {
                return ProjectToolSupport.error("No program currently loaded");
            }

            if (!(arguments.get("pattern") instanceof String pattern) || pattern.isBlank()) {
                return ProjectToolSupport.error("pattern is required");
            }

            final int limit;
            try {
                limit = QueryPageBounds.integer(arguments, "limit", DEFAULT_LIMIT, 1, QueryPageBounds.MAX_LIMIT);
            } catch (IllegalArgumentException e) {
                return ProjectToolSupport.error(e.getMessage());
            }

            ParsedPattern parsed;
            try {
                parsed = parsePattern(pattern);
            } catch (IllegalArgumentException e) {
                return ProjectToolSupport.error("Invalid pattern format: " + e.getMessage()
                    + ". Expected hex bytes like '48 8b c1' or '48 ?? c1' for wildcards");
            }

            Address rangeStart;
            Address rangeEnd;
            try {
                rangeStart = parseOptionalAddress(program, arguments.get("start_address"), "start_address");
                rangeEnd = parseOptionalAddress(program, arguments.get("end_address"), "end_address");
            } catch (IllegalArgumentException e) {
                return ProjectToolSupport.error(e.getMessage());
            }
            if (rangeStart != null && rangeEnd != null) {
                String rangeError = InstructionMaskBuilder.validateScanRange(rangeStart, rangeEnd);
                if (rangeError != null) return ProjectToolSupport.error(rangeError);
            }

            TaskMonitor monitor = task == null ? TaskMonitor.DUMMY : new McpTaskMonitor(task, 0, 100, "Search bytes");
            ScanOutcome scan = search(program, parsed.bytes, parsed.mask, limit, rangeStart, rangeEnd, monitor);
            MatcherContracts.ScanStatus status = MatcherContracts.scanStatus(
                scan.matches.size(), limit, scan.moreExist, scan.cancelled, scan.finishedAllRanges);

            String programId = ProgramIdentity.id(program);
            String revision = Long.toString(program.getModificationNumber());
            List<Map<String, Object>> matches = new ArrayList<>();
            for (Hit hit : scan.matches) {
                matches.add(hitRecord(program, hit, programId, revision));
            }

            Map<String, Object> body = new LinkedHashMap<>();
            body.put("program_id", programId);
            body.put("program_name", program.getName());
            body.put("modification_number", revision);
            body.put("pattern", pattern);
            body.put("start_address", rangeStart == null ? null : rangeStart.toString());
            body.put("end_address", rangeEnd == null ? null : rangeEnd.toString());
            body.put("scan_scope", "executable_loaded_memory");
            body.put("blocks_scanned", scan.blocksScanned);
            body.putAll(MatcherContracts.scanFields(status));
            body.put("matches", matches);

            String summary = "Byte search: " + scan.matches.size() + " match(es), unique="
                + status.unique() + ", scan_complete=" + status.scanComplete()
                + ", scan_truncated=" + status.scanTruncated()
                + ". A result cap cannot establish uniqueness.";
            return BatchQuerySupport.boundedResult(body);
        } catch (IllegalArgumentException e) {
            return ProjectToolSupport.error(e.getMessage());
        } finally {
            if (lease != null) lease.close();
        }
    }

    private static ScanOutcome search(Program program, byte[] pattern, byte[] mask, int limit,
            Address rangeStart, Address rangeEnd, TaskMonitor monitor) {
        ScanOutcome outcome = new ScanOutcome();
        Memory memory = program.getMemory();
        List<MemoryBlock> blocks = scannableBlocks(program, rangeStart, rangeEnd);
        outcome.blocksScanned = 0;
        try {
            for (MemoryBlock block : blocks) {
                monitor.checkCancelled();
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
                    Address hit = memory.findBytes(addr, searchEnd, pattern, mask, true, monitor);
                    if (hit == null) break;
                    if (outcome.matches.size() >= limit) {
                        outcome.moreExist = true;
                        outcome.finishedAllRanges = false;
                        return outcome;
                    }
                    outcome.matches.add(new Hit(hit, block.getName()));
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

    private static Map<String, Object> hitRecord(Program program, Hit hit, String programId, String revision) {
        Function containing = program.getFunctionManager().getFunctionContaining(hit.address);
        Function atEntry = program.getFunctionManager().getFunctionAt(hit.address);
        String position;
        if (atEntry != null) position = "entry";
        else if (containing != null) position = "interior";
        else position = "block";

        Map<String, Object> item = new LinkedHashMap<>();
        item.put("address", hit.address.toString());
        item.put("space", hit.address.getAddressSpace().getName());
        item.put("block_name", hit.blockName);
        if (containing != null) {
            Map<String, Object> function = new LinkedHashMap<>();
            function.put("name", containing.getName(true));
            function.put("entry", containing.getEntryPoint().toString());
            function.put("size", containing.getBody().getNumAddresses());
            item.put("containing_function", function);
        } else {
            item.put("containing_function", null);
        }
        item.put("at_entry", atEntry != null);
        item.put("position", position);
        item.put("program_id", programId);
        item.put("modification_number", revision);
        return item;
    }

    private static String programSelector(Map<String, Object> arguments) {
        String selected = null;
        for (String key : List.of("program", "program_name", "program_id")) {
            if (!arguments.containsKey(key)) continue;
            if (!(arguments.get(key) instanceof String value) || value.isBlank()) {
                throw new IllegalArgumentException(key + " must be a nonblank string");
            }
            String trimmed = value.trim();
            if (selected == null) selected = trimmed;
        }
        return selected;
    }

    private static Address parseOptionalAddress(Program program, Object raw, String name) {
        if (raw == null) return null;
        if (!(raw instanceof String value) || value.isBlank()) throw new IllegalArgumentException(name + " must be a nonblank string");
        Address address = program.getAddressFactory().getAddress(value.trim());
        if (address == null) throw new IllegalArgumentException("Invalid " + name + ": " + value);
        return address;
    }

    private static ParsedPattern parsePattern(String pattern) {
        if (pattern.length() > InstructionMaskBuilder.MAX_PATTERN_BYTES * 4)
            throw new IllegalArgumentException("pattern text exceeds bounded size");
        String normalized = pattern.replaceAll("[\\s,]", "");
        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("Pattern must have even number of hex characters");
        }
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Pattern must contain at least one byte");
        }

        int length = normalized.length() / 2;
        if (length > InstructionMaskBuilder.MAX_PATTERN_BYTES)
            throw new IllegalArgumentException("pattern exceeds " + InstructionMaskBuilder.MAX_PATTERN_BYTES + " bytes");
        byte[] bytes = new byte[length];
        byte[] mask = new byte[length];

        for (int i = 0; i < length; i++) {
            String byteStr = normalized.substring(i * 2, i * 2 + 2);
            if (byteStr.equals("??") || byteStr.equals("**")) {
                bytes[i] = 0;
                mask[i] = 0;
            } else {
                try {
                    bytes[i] = (byte) Integer.parseInt(byteStr, 16);
                    mask[i] = (byte) 0xFF;
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException("Invalid hex byte: " + byteStr);
                }
            }
        }
        return new ParsedPattern(bytes, mask);
    }

    private static final class ParsedPattern {
        final byte[] bytes;
        final byte[] mask;
        ParsedPattern(byte[] bytes, byte[] mask) {
            this.bytes = bytes;
            this.mask = mask;
        }
    }

    private static final class ScanOutcome {
        final List<Hit> matches = new ArrayList<>();
        boolean moreExist;
        boolean cancelled;
        boolean finishedAllRanges;
        int blocksScanned;
    }

    private static final class Hit {
        final Address address;
        final String blockName;
        Hit(Address address, String blockName) {
            this.address = address;
            this.blockName = blockName;
        }
    }
}
