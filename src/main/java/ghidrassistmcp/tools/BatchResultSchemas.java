package ghidrassistmcp.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Completed-result contracts for the bounded batch tools, including partial row failures. */
final class BatchResultSchemas {
    private BatchResultSchemas() {}
    static Map<String, Object> text() { return Map.of("type", "string"); }
    static Map<String, Object> bool() { return Map.of("type", "boolean"); }
    static Map<String, Object> described(Map<String, Object> schema, String description) {
        Map<String, Object> result = new LinkedHashMap<>(schema);
        result.put("description", description);
        return result;
    }
    static Map<String, Object> number(int minimum, int maximum) {
        return Map.of("type", "integer", "minimum", minimum, "maximum", maximum);
    }
    static Map<String, Object> nonnegative() { return Map.of("type", "integer", "minimum", 0); }
    static Map<String, Object> array(Object items, int max) {
        return Map.of("type", "array", "items", items, "maxItems", max);
    }
    static Map<String, Object> object(Map<String, Object> properties, String... required) {
        return Map.of("type", "object", "properties", properties, "required", List.of(required));
    }
    static Map<String, Object> nullableText() { return Map.of("type", List.of("string", "null")); }
    static Map<String, Object> properties(Object... entries) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < entries.length; i += 2) result.put((String) entries[i], entries[i + 1]);
        return result;
    }
    static Map<String, Object> row(Map<String, Object> properties, String... successRequired) {
        Map<String, Object> result = new LinkedHashMap<>(object(properties));
        result.put("anyOf", List.of(Map.of("required", List.of(successRequired)), Map.of("required", List.of("error"))));
        return result;
    }
    static Map<String, Object> addressProperties() {
        return properties("address", text(), "space", text(), "offset", Map.of("type", "string", "pattern", "^[0-9]+$"));
    }
    static Map<String, Object> symbol() {
        return object(properties("name", text(), "address", text(), "space", text(), "type", text(), "source", text()),
            "name", "address", "space", "type", "source");
    }
    static Map<String, Object> function() {
        return object(properties("name", text(), "entry", text(), "space", text(), "size", nonnegative()),
            "name", "entry", "space", "size");
    }
    static Map<String, Object> bytesProperties() {
        return properties("requested", number(0, 65536), "read", number(0, 65536), "address", text(), "space", text(),
            "hex", Map.of("type", "string", "pattern", "^(?:[0-9a-f]{2})*$", "maxLength", 131072),
            "truncated", bool(), "warnings", array(text(), 1));
    }
    static Map<String, Object> bytes() {
        return object(bytesProperties(), "requested", "read", "address", "space", "hex", "truncated");
    }
    static Map<String, Object> integerValue() {
        // 64-bit values intentionally remain decimal strings to avoid JSON consumer precision loss.
        return Map.of("anyOf", List.of(Map.of("type", "integer"), Map.of("type", "string", "pattern", "^-?[0-9]+$")));
    }
    static Map<String, Object> context() {
        Map<String, Object> item = addressProperties();
        item.putAll(properties("function", function(), "symbols", array(symbol(), 32),
            "data", object(properties("address", text(), "type", text(), "length", nonnegative()), "address", "type", "length"),
            "instruction", object(properties("address", text(), "text", text(), "length", nonnegative()), "address", "text", "length"),
            "bytes", bytes(), "xrefs", array(object(properties("direction", Map.of("const", "to"), "from", text(), "to", text(), "type", text()),
                "direction", "from", "to", "type"), 1000),
            "truncated", bool(), "symbol_limit", Map.of("const", 32), "symbols_truncated", bool(), "error", nullableText()));
        return object(properties("results", array(row(item, "address", "space", "offset", "symbols", "bytes", "xrefs", "truncated", "symbol_limit", "symbols_truncated"), 1000),
            "count", number(0, 1000), "errors", described(number(0, 1000), "Number of rows carrying an error; successful rows remain usable."),
            "truncated", described(bool(), "At least one address has omitted xrefs."),
            "partial", described(bool(), "At least one row failed, a memory read was short, or symbol/xref output was capped.")),
            "results", "count", "errors", "truncated", "partial");
    }
    static Map<String, Object> symbols() {
        return object(properties("results", array(object(properties("query", text(), "matches", array(symbol(), 1000),
            "scanned", number(0, 100000), "truncated", bool()), "query", "matches", "scanned", "truncated"), 64),
            "count", number(0, 64), "truncated", bool()), "results", "count", "truncated");
    }
    static Map<String, Object> memory() {
        Map<String, Object> item = bytesProperties();
        item.putAll(properties("type", Map.of("enum", List.of("bytes", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64")),
            "endian", Map.of("enum", List.of("big", "little")), "value", integerValue(), "value_error", text(), "error", nullableText()));
        return object(properties("results", array(row(item, "requested", "read", "address", "space", "hex", "truncated", "type", "endian"), 1000),
            "count", number(0, 1000), "total_bytes", described(number(0, BatchQuerySupport.MAX_BYTES), "Requested bytes charged against the batch budget, including address failures; not bytes successfully read."),
            "errors", described(number(0, 1000), "Number of rows with an exception; short reads are reported in read/truncated/value_error instead."),
            "truncated", described(bool(), "At least one memory range was read only partially."),
            "partial", described(bool(), "At least one row failed or a memory read was short.")), "results", "count", "total_bytes", "errors", "truncated", "partial");
    }
    static Map<String, Object> table() {
        Map<String, Object> item = new LinkedHashMap<>(object(properties("index", number(0, 999), "address", text(), "error", nullableText()), "index"));
        item.put("anyOf", List.of(Map.of("required", List.of("address")), Map.of("required", List.of("error"))));
        item.put("additionalProperties", Map.of("anyOf", List.of(integerValue(),
            object(properties("error", Map.of("const", "short_read"), "bytes", bytes()), "error", "bytes"))));
        return object(properties("rows", array(item, 1000), "count", number(0, 1000), "errors", number(0, 1000),
            "truncated", bool(), "partial", bool()), "rows", "count", "errors", "truncated", "partial");
    }
    static Map<String, Object> reference() {
        Map<String, Object> item = properties("direction", Map.of("enum", List.of("to", "from")),
            "from", text(), "to", text(), "type", text(), "from_space", text(), "to_space", text(),
            "operand_index", Map.of("type", "integer"), "source", text(), "primary", bool(), "external", bool(),
            "flow", object(properties("call", bool(), "jump", bool(), "read", bool(), "write", bool(), "indirect", bool(), "data", bool()),
                "call", "jump", "read", "write", "indirect", "data"),
            "external_location", object(properties("library", text(), "label", text(), "original_name", text(), "address", text()),
                "library", "label", "original_name", "address"),
            "from_function", function(), "to_function", function(), "from_symbols", array(symbol(), 32), "to_symbols", array(symbol(), 32),
            "symbol_limit", Map.of("const", 32), "from_symbols_truncated", bool(), "to_symbols_truncated", bool());
        return object(item, "direction", "from", "to", "type", "from_space", "to_space", "operand_index", "source", "primary", "external",
            "flow", "from_symbols", "to_symbols", "symbol_limit", "from_symbols_truncated", "to_symbols_truncated");
    }
    static Map<String, Object> xrefs() {
        Map<String, Object> item = addressProperties();
        item.putAll(properties("xrefs", array(reference(), 1000), "truncated", bool(), "error", nullableText()));
        return object(properties("results", array(row(item, "address", "space", "offset", "xrefs", "truncated"), 1000),
            "count", number(0, 1000), "errors", number(0, 1000), "scanned", number(0, 100000),
            "scan_limit", number(1, 100000), "truncated", bool(), "partial", bool()),
            "results", "count", "errors", "scanned", "scan_limit", "truncated", "partial");
    }
    static Map<String, Object> inventory() {
        Map<String, Object> edge = object(properties("name", text(), "address", text()), "name", "address");
        Map<String, Object> item = object(properties("name", text(), "address", text(), "size", nonnegative(),
            "entry_bytes", Map.of("type", "string", "pattern", "^(?:[0-9a-f]{2})*$", "maxLength", 8192),
            "entry_sha256", Map.of("type", "string", "pattern", "^[0-9a-f]{64}$"),
            "callers", nonnegative(), "callees", nonnegative(), "caller_edges", array(edge, 1000), "callee_edges", array(edge, 1000),
            "caller_edges_truncated", bool(), "callee_edges_truncated", bool()),
            "name", "address", "size", "entry_bytes", "entry_sha256", "callers", "callees");
        return object(properties("program", text(), "offset", number(0, Integer.MAX_VALUE), "limit", number(0, 1000),
            "scan_limit", number(1, 1000000), "scanned", number(0, 1000000), "total_matched", number(0, 1000000),
            "truncated", bool(), "scan_truncated", bool(),
            "total_matched_is_exact", described(bool(), "False when the scan ceiling makes total_matched a lower bound."),
            "next_offset", described(Map.of("type", List.of("integer", "null"), "minimum", 0),
                "Next matching-record offset only when an additional scanned match exists and this page advanced. Null for empty/zero-size/final known pages. Increase scan_limit when scan_truncated is true; offsets do not resume a scan."),
            "functions", array(item, 1000)),
            "program", "offset", "limit", "scan_limit", "scanned", "total_matched", "truncated", "scan_truncated", "total_matched_is_exact", "next_offset", "functions");
    }
}
