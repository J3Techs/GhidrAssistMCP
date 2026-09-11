package ghidrassistmcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.*;

public class ReadMemoryBatchTool implements McpTool {
  public String getName() {
    return "read_memory_batch";
  }

  public String getDescription() {
    return "Batch bounded read-only memory ranges with optional typed integer decoding.";
  }

  public McpSchema.JsonSchema getInputSchema() {
    return new McpSchema.JsonSchema(
        "object",
        Map.of(
            "ranges",
            Map.of(
                "type",
                "array",
                "items",
                Map.of(
                    "type",
                    "object",
                    "properties",
                    Map.of(
                        "address", Map.of("type", "string"), "length", Map.of("type", "integer")),
                    "required",
                    List.of("address"))),
            "length",
            Map.of("type", "integer"),
            "type",
            Map.of(
                "type",
                "string",
                "enum",
                List.of("bytes", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64")),
            "endian",
            Map.of("type", "string", "enum", List.of("big", "little"), "default", "big")),
        List.of("ranges"),
        null,
        null,
        null);
  }

  public McpSchema.CallToolResult execute(Map<String, Object> a, Program p) {
    try {
      if (p == null) return ProjectToolSupport.error("No program currently loaded");
      List<?> rs = BatchQuerySupport.list(a.get("ranges"), "ranges", BatchQuerySupport.MAX_ROWS);
      String typ = a.getOrDefault("type", "bytes").toString(),
          end = a.getOrDefault("endian", "big").toString();
      if (!List.of("big", "little").contains(end)) throw new IllegalArgumentException("invalid endian");
      if (!typ.equals("bytes") && width(typ) == 0) throw new IllegalArgumentException("invalid type");
      int def = BatchQuerySupport.integer(a, "length", 16, 65536), total = 0, errors = 0;
      List<Object> out = new ArrayList<>();
      for (Object x : rs) {
        Map<String, Object> row = new LinkedHashMap<>();
        try {
          if (!(x instanceof Map<?, ?> m))
            throw new IllegalArgumentException("ranges entries must be objects");
          String s = BatchQuerySupport.text(m.get("address"), "address");
          @SuppressWarnings("unchecked")
          int n = BatchQuerySupport.integer((Map<String, Object>) m, "length", def, 65536);
          if (n < 1 || n > 65536) throw new IllegalArgumentException("length must be 1..65536");
          if (!typ.equals("bytes")) {
            int w = width(typ);
            if (n != w) n = w;
          }
          total = BatchQuerySupport.checkedTotal(total, n);
          Address ad = BatchQuerySupport.address(p, s);
          row.putAll(BatchQuerySupport.bytes(p, ad, n));
          row.put("type", typ);
          row.put("endian", end);
          if (n == width(typ) && !typ.equals("bytes")) {
            String h = (String) row.get("hex");
            if (h.length() == n * 2) row.put("value", decode(h, end, typ));
            else row.put("value_error", "short read");
          }
        } catch (Exception e) {
          errors++;
          row.put("error", e.getMessage());
        }
        out.add(row);
      }
      return ProjectToolSupport.result(
          Map.of(
              "results",
              out,
              "count",
              out.size(),
              "total_bytes",
              total,
              "errors",
              errors,
              "truncated",
              false));
    } catch (Exception e) {
      return ProjectToolSupport.error(e.getMessage());
    }
  }

  private static int width(String t) {
    return switch (t) {
      case "u8", "i8" -> 1;
      case "u16", "i16" -> 2;
      case "u32", "i32" -> 4;
      case "u64", "i64" -> 8;
      default -> 0;
    };
  }

  private static Object decode(String h, String e, String t) {
    return BatchQuerySupport.decodeInteger(h, e, t);
  }
}
