package ghidrassistmcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.*;

public class ReadMemoryTableTool implements McpTool {
  public String getName() {
    return "read_memory_table";
  }

  public String getDescription() {
    return "Read a bounded memory table using explicit row stride and typed fields.";
  }

  public McpSchema.JsonSchema getInputSchema() {
    return new McpSchema.JsonSchema(
        "object",
        Map.of(
            "base",
            Map.of("type", "string"),
            "rows",
            Map.of("type", "integer"),
            "stride",
            Map.of("type", "integer"),
            "fields",
            Map.of(
                "type",
                "array",
                "items",
                Map.of(
                    "type",
                    "object",
                    "properties",
                    Map.of(
                        "name",
                        Map.of("type", "string"),
                        "offset",
                        Map.of("type", "integer"),
                        "width",
                        Map.of("type", "integer"),
                        "type", Map.of("type", "string", "enum", List.of("u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64"))),
                    "required",
                    List.of("offset", "width"))),
            "endian",
            Map.of("type", "string", "enum", List.of("big", "little"), "default", "little")),
        List.of("base", "rows", "stride", "fields"),
        null,
        null,
        null);
  }

  public McpSchema.CallToolResult execute(Map<String, Object> a, Program p) {
    try {
      if (p == null) return ProjectToolSupport.error("No program currently loaded");
      Address base = BatchQuerySupport.address(p, BatchQuerySupport.text(a.get("base"), "base"));
      int rows = BatchQuerySupport.integer(a, "rows", 1, BatchQuerySupport.MAX_ROWS),
          stride = BatchQuerySupport.integer(a, "stride", 1, 65536);
      List<?> fs = BatchQuerySupport.list(a.get("fields"), "fields", BatchQuerySupport.MAX_FIELDS);
      if (stride == 0) throw new IllegalArgumentException("stride must be positive");
      String end = a.getOrDefault("endian", "little").toString();
      if (!end.equals("little") && !end.equals("big"))
        throw new IllegalArgumentException("invalid endian");
      Set<String> fieldNames = new HashSet<>();
      for (Object f : fs) {
        if (!(f instanceof Map<?, ?> m)
            || !(m.get("offset") instanceof Number)
            || !(m.get("width") instanceof Number))
          throw new IllegalArgumentException("fields require offset and width");
        @SuppressWarnings("unchecked") Map<String, Object> spec = (Map<String, Object>) m;
        int off = BatchQuerySupport.integer(spec, "offset", 0, 65536),
            w = BatchQuerySupport.integer(spec, "width", 1, 8);
        if (!List.of(1, 2, 4, 8).contains(w) || off + w > stride)
          throw new IllegalArgumentException("field outside stride");
        String name = m.get("name") instanceof String ? (String) m.get("name") : "field_" + off;
        if (name.isBlank() || List.of("index", "address", "error").contains(name) || !fieldNames.add(name))
          throw new IllegalArgumentException("field name is reserved, empty or duplicated: " + name);
        String type = spec.getOrDefault("type", "u" + (w * 8)).toString();
        if (!type.equals("u" + (w * 8)) && !type.equals("i" + (w * 8)))
          throw new IllegalArgumentException("field type must agree with width");
      }
      if ((long) rows * stride > BatchQuerySupport.MAX_BYTES)
        throw new IllegalArgumentException("total byte budget exceeded");
      List<Object> result = new ArrayList<>();
      int errors = 0;
      for (int i = 0; i < rows; i++) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("index", i);
        try {
          Address ad = base.add((long) i * stride);
          row.put("address", ad.toString());
          for (Object f : fs) {
            Map<?, ?> m = (Map<?, ?>) f;
            int off = ((Number) m.get("offset")).intValue(),
                w = ((Number) m.get("width")).intValue();
            String name = m.get("name") instanceof String ? (String) m.get("name") : "field_" + off;
            if (name.equals("index") || name.equals("address"))
              throw new IllegalArgumentException("field name reserved: " + name);
            Map<String, Object> b = BatchQuerySupport.bytes(p, ad.add(off), w);
            row.put(
                name,
                b.get("truncated") instanceof Boolean && ((Boolean) b.get("truncated"))
                    ? Map.of("error", "short_read", "bytes", b)
                    : BatchQuerySupport.decodeInteger((String) b.get("hex"), end,
                        m.get("type") == null ? "u" + (w * 8) : m.get("type").toString()));
          }
        } catch (Exception e) {
          errors++;
          row.put("error", e.getMessage());
        }
        result.add(row);
      }
      return ProjectToolSupport.result(
          Map.of("rows", result, "count", result.size(), "errors", errors, "truncated", false));
    } catch (Exception e) {
      return ProjectToolSupport.error(e.getMessage());
    }
  }

  private static Object decode(String h, String e, int w) {
    if (h.length() != w * 2) return Map.of("error", "short_read");
    return BatchQuerySupport.decodeInteger(h, e, "u" + (w * 8));
  }
}
