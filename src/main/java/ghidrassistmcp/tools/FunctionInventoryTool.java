/* Structured, bounded function inventory for cross-binary analysis. */
package ghidrassistmcp.tools;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Emits stable structured records without requiring callers to parse prose. */
public class FunctionInventoryTool implements McpTool {
    private static final int MAX_LIMIT = 1000;
    private static final int MAX_BYTES = 4096;

    @Override public String getName() { return "function_inventory"; }
    @Override public String getDescription() {
        return "Export a bounded paginated JSON function inventory with entry-byte prefix/hash and optional caller/callee edges";
    }
    @Override public boolean isCacheable() { return true; }
    @Override public boolean isLongRunning() { return true; }

    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.ofEntries(
            Map.entry("offset", Map.of("type", "integer", "default", 0)),
            Map.entry("limit", Map.of("type", "integer", "default", 100)),
            Map.entry("scan_limit", Map.of("type", "integer", "default", 10000)),
            Map.entry("max_bytes", Map.of("type", "integer", "default", 32)),
            Map.entry("pattern", Map.of("type", "string")),
            Map.entry("match_mode", Map.of("type", "string", "enum",
                List.of("contains", "wildcard", "regex", "starts_with", "ends_with"), "default", "contains")),
            Map.entry("case_sensitive", Map.of("type", "boolean", "default", true)),
            Map.entry("range_start", Map.of("type", "string")),
            Map.entry("range_end", Map.of("type", "string")),
            Map.entry("include_edges", Map.of("type", "boolean", "default", false)),
            Map.entry("edge_limit", Map.of("type", "integer", "default", 100))
        ), List.of(), null, null, null);
    }

    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return run(args, program, TaskMonitor.DUMMY);
    }

    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
            GhidrAssistMCPBackend backend, McpTask task) {
        return run(args, program, new McpTaskMonitor(task, 0, 100, "Function inventory"));
    }

    private McpSchema.CallToolResult run(Map<String, Object> args, Program program, TaskMonitor monitor) {
        if (program == null) return ProjectToolSupport.error("No program currently loaded");
        try {
            int offset = integer(args, "offset", 0, 0, Integer.MAX_VALUE);
            int limit = integer(args, "limit", 100, 0, MAX_LIMIT);
            int scanLimit = integer(args, "scan_limit", 10000, 1, 1_000_000);
            int maxBytes = integer(args, "max_bytes", 32, 0, MAX_BYTES);
            int edgeLimit = integer(args, "edge_limit", 100, 0, MAX_LIMIT);
            Address start = parseAddress(program, args.get("range_start"));
            Address end = parseAddress(program, args.get("range_end"));
            if (start != null && end != null && start.compareTo(end) > 0)
                throw new IllegalArgumentException("range_start must not exceed range_end");

            Predicate<String> matcher = matcher(string(args, "pattern", null),
                string(args, "match_mode", "contains"), bool(args, "case_sensitive", true));
            boolean includeEdges = bool(args, "include_edges", false);
            List<Map<String, Object>> records = new ArrayList<>();
            int scanned = 0;
            int matched = 0;
            boolean scanTruncated = false;
            FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                if (++scanned > scanLimit) { scanTruncated = true; break; }
                Function function = iterator.next();
                Address entry = function.getEntryPoint();
                if ((start != null && entry.compareTo(start) < 0)
                        || (end != null && entry.compareTo(end) > 0)) continue;
                if (matcher != null && !matcher.test(function.getName(true)) && !matcher.test(function.getName())) continue;
                matched++;
                if (matched <= offset || records.size() >= limit) continue;
                records.add(record(program, function, maxBytes, includeEdges, edgeLimit, monitor));
            }
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("program", program.getName());
            result.put("offset", offset);
            result.put("limit", limit);
            result.put("scan_limit", scanLimit);
            result.put("scanned", Math.min(scanned, scanLimit));
            result.put("total_matched", matched);
            result.put("truncated", scanTruncated || matched > (long) offset + records.size());
            result.put("scan_truncated", scanTruncated);
            result.put("functions", records);
            return ProjectToolSupport.result(result);
        } catch (Exception e) {
            return ProjectToolSupport.error(e.getMessage());
        }
    }

    private static Map<String, Object> record(Program program, Function function, int maxBytes,
                                               boolean includeEdges, int edgeLimit, TaskMonitor monitor) {
        Address entry = function.getEntryPoint();
        int contiguous = (int) Math.min(Integer.MAX_VALUE,
            Math.min(maxBytes, function.getBody().getRangeContaining(entry).getMaxAddress().subtract(entry) + 1));
        byte[] bytes = readContiguous(program.getMemory(), entry, contiguous);
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("name", function.getName(true));
        item.put("address", entry.toString());
        item.put("size", function.getBody().getNumAddresses());
        item.put("entry_bytes", HexFormat.of().formatHex(bytes));
        item.put("entry_sha256", sha256(bytes));
        Set<Function> callers = function.getCallingFunctions(monitor);
        Set<Function> callees = function.getCalledFunctions(monitor);
        item.put("callers", callers.size());
        item.put("callees", callees.size());
        if (includeEdges) {
            item.put("caller_edges", edges(callers, edgeLimit));
            item.put("callee_edges", edges(callees, edgeLimit));
            item.put("caller_edges_truncated", callers.size() > edgeLimit);
            item.put("callee_edges_truncated", callees.size() > edgeLimit);
        }
        return item;
    }

    private static List<Map<String, Object>> edges(Set<Function> functions, int limit) {
        List<Function> ordered = new ArrayList<>(functions);
        ordered.sort(Comparator.comparing(f -> f.getEntryPoint().toString()));
        List<Map<String, Object>> result = new ArrayList<>();
        for (int i = 0; i < ordered.size() && i < limit; i++) {
            Function f = ordered.get(i);
            result.add(Map.of("name", f.getName(true), "address", f.getEntryPoint().toString()));
        }
        return result;
    }

    private static byte[] readContiguous(Memory memory, Address address, int count) {
        byte[] bytes = new byte[count];
        for (int i = 0; i < count; i++) {
            try { bytes[i] = memory.getByte(address.add(i)); }
            catch (MemoryAccessException e) { return java.util.Arrays.copyOf(bytes, i); }
        }
        return bytes;
    }

    private static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }

    private static Predicate<String> matcher(String value, String mode, boolean sensitive) {
        if (!List.of("contains", "wildcard", "regex", "starts_with", "ends_with").contains(mode))
            throw new IllegalArgumentException("Invalid match_mode");
        if (value == null || value.isBlank()) return null;
        String expression = sensitive ? value : value.toLowerCase(java.util.Locale.ROOT);
        if ("wildcard".equals(mode)) {
            StringBuilder regex = new StringBuilder("^");
            for (char c : expression.toCharArray()) {
                if (c == '*') regex.append(".*");
                else if (c == '?') regex.append('.');
                else regex.append(Pattern.quote(String.valueOf(c)));
            }
            Pattern pattern = Pattern.compile(regex.append('$').toString(),
                sensitive ? 0 : Pattern.CASE_INSENSITIVE);
            return name -> pattern.matcher(name).matches();
        }
        if ("regex".equals(mode)) {
            Pattern pattern = Pattern.compile(value, sensitive ? 0 : Pattern.CASE_INSENSITIVE);
            return name -> pattern.matcher(name).matches();
        }
        return name -> {
            String candidate = sensitive ? name : name.toLowerCase(java.util.Locale.ROOT);
            return switch (mode) {
                case "starts_with" -> candidate.startsWith(expression);
                case "ends_with" -> candidate.endsWith(expression);
                default -> candidate.contains(expression);
            };
        };
    }

    private static int integer(Map<String, Object> args, String key, int fallback, int min, int max) {
        Object value = args.get(key);
        if (value == null) return fallback;
        if (!(value instanceof Number) || value instanceof Float || value instanceof Double)
            throw new IllegalArgumentException(key + " must be an integer");
        long number;
        try { number = new java.math.BigDecimal(value.toString()).longValueExact(); }
        catch (ArithmeticException e) { throw new IllegalArgumentException(key + " exceeds integer bounds"); }
        if (number < min || number > max) throw new IllegalArgumentException(key + " must be between " + min + " and " + max);
        return (int) number;
    }

    private static Address parseAddress(Program program, Object value) {
        if (!(value instanceof String) || ((String) value).isBlank()) return null;
        Address address = program.getAddressFactory().getAddress((String) value);
        if (address == null) throw new IllegalArgumentException("Invalid address: " + value);
        return address;
    }

    private static String string(Map<String, Object> args, String key, String fallback) {
        return args.get(key) instanceof String ? (String) args.get(key) : fallback;
    }

    private static boolean bool(Map<String, Object> args, String key, boolean fallback) {
        return args.get(key) instanceof Boolean ? (Boolean) args.get(key) : fallback;
    }
}
