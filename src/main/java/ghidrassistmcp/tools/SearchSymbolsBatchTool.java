package ghidrassistmcp.tools;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.*;

public class SearchSymbolsBatchTool implements McpTool {
  @Override public Map<String, Object> getOutputSchema() { return BatchResultSchemas.symbols(); }

  public String getName() {
    return "search_symbols_batch";
  }

  public String getDescription() {
    return "Batch read-only symbol search with exact, contains, or glob matching and type/source"
               + " filters.";
  }

  public McpSchema.JsonSchema getInputSchema() {
    return new McpSchema.JsonSchema(
        "object",
        Map.of(
            "queries",
            Map.of("type", "array", "minItems", 1, "maxItems", 64, "items", Map.of("type", "string", "minLength", 1)),
            "mode",
            Map.of(
                "type",
                "string",
                "enum",
                List.of("exact", "contains", "glob"),
                "default",
                "contains"),
            "symbol_type",
            Map.of("type", "string"),
            "source",
            Map.of("type", "string"),
            "limit",
            Map.of("type", "integer", "minimum", 0, "maximum", 1000, "default", 500),
            "scan_limit",
            Map.of("type", "integer", "minimum", 0, "maximum", 100000, "default", 10000)),
        List.of("queries"),
        null,
        null,
        null);
  }

  public McpSchema.CallToolResult execute(Map<String, Object> a, Program p) {
    try {
      if (p == null) return ProjectToolSupport.error("No program currently loaded");
      List<?> qs = BatchQuerySupport.list(a.get("queries"), "queries", 64);
      String mode = a.getOrDefault("mode", "contains").toString();
      if (!List.of("exact", "contains", "glob").contains(mode))
        throw new IllegalArgumentException("invalid mode");
      int lim = BatchQuerySupport.integer(a, "limit", 500, BatchQuerySupport.MAX_ROWS),
          scan = BatchQuerySupport.integer(a, "scan_limit", 10000, 100000);
      String typ = (String) a.get("symbol_type"), src = (String) a.get("source");
      List<Object> outRows = new ArrayList<>();
      boolean trunc = false;
      for (Object q0 : qs) {
        String q = BatchQuerySupport.text(q0, "query");
        List<Object> ms = new ArrayList<>();
        if (lim == 0) {
          outRows.add(Map.of("query", q, "matches", ms, "scanned", 0, "truncated", true));
          trunc = true;
          continue;
        }
        int scanned = 0;
        var it = p.getSymbolTable().getAllSymbols(true);
        while (it.hasNext() && scanned < scan) {
          scanned++;
          Symbol s = it.next();
          if (typ != null && !String.valueOf(s.getSymbolType()).equalsIgnoreCase(typ)) continue;
          if (src != null && !String.valueOf(s.getSource()).equalsIgnoreCase(src)) continue;
          if (BatchQuerySupport.matches(s.getName(true), q, mode) || BatchQuerySupport.matches(s.getName(), q, mode)) {
            ms.add(BatchQuerySupport.symbol(s));
            if (ms.size() >= lim) {
              trunc = true;
              break;
            }
          }
        }
        boolean scanTruncated = it.hasNext();
        trunc |= scanTruncated;
        outRows.add(
            Map.of(
                "query",
                q,
                "matches",
                ms,
                "scanned",
                scanned,
                "truncated",
                ms.size() >= lim || scanTruncated));
      }
      return BatchQuerySupport.boundedResult(
          Map.of("results", outRows, "count", outRows.size(), "truncated", trunc));
    } catch (Exception e) {
      return ProjectToolSupport.error(e.getMessage());
    }
  }
}
