package ghidrassistmcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.*;

public class XrefsBatchTool implements McpTool {
  public String getName() {
    return "xrefs_batch";
  }

  public String getDescription() {
    return "Batch bounded cross-reference lookup enriched with endpoint functions and symbols.";
  }

  public McpSchema.JsonSchema getInputSchema() {
    return new McpSchema.JsonSchema(
        "object",
        Map.of(
            "addresses",
            Map.of("type", "array", "items", Map.of("type", "string")),
            "direction",
            Map.of("type", "string", "enum", List.of("to", "from", "both"), "default", "both"),
            "per_address_limit",
            Map.of("type", "integer", "default", 100)),
        List.of("addresses"),
        null,
        null,
        null);
  }

  public McpSchema.CallToolResult execute(Map<String, Object> a, Program p) {
    try {
      if (p == null) return ProjectToolSupport.error("No program currently loaded");
      List<?> as =
          BatchQuerySupport.list(a.get("addresses"), "addresses", BatchQuerySupport.MAX_ROWS);
      String dir = a.getOrDefault("direction", "both").toString();
      if (!List.of("to", "from", "both").contains(dir))
        throw new IllegalArgumentException("invalid direction");
      int lim = BatchQuerySupport.integer(a, "per_address_limit", 100, 1000);
      if ((long) lim * as.size() > 10000) throw new IllegalArgumentException("total xref limit exceeds 10000; reduce addresses or per_address_limit");
      List<Object> rows = new ArrayList<>();
      int errors = 0;
      for (Object o : as) {
        Map<String, Object> row = new LinkedHashMap<>();
        try {
          Address ad = BatchQuerySupport.address(p, BatchQuerySupport.text(o, "address"));
          row.putAll(BatchQuerySupport.addr(ad));
          List<Object> x = new ArrayList<>();
          boolean truncated = false;
          if (dir.equals("to") || dir.equals("both")) {
            ReferenceIterator it = p.getReferenceManager().getReferencesTo(ad);
            while (it.hasNext() && x.size() < lim) x.add(ref(p, it.next(), "to"));
            truncated |= it.hasNext();
          }
          if (dir.equals("from") || dir.equals("both")) {
            for (Reference q : p.getReferenceManager().getReferencesFrom(ad)) {
              if (x.size() >= lim) { truncated = true; break; }
              x.add(ref(p, q, "from"));
            }
          }
          row.put("xrefs", x);
          row.put("truncated", truncated);
        } catch (Exception e) {
          errors++;
          row.put("error", e.getMessage());
        }
        rows.add(row);
      }
      return ProjectToolSupport.result(
          Map.of("results", rows, "count", rows.size(), "errors", errors, "truncated",
              rows.stream().anyMatch(row -> Boolean.TRUE.equals(((Map<?, ?>) row).get("truncated")))));
    } catch (Exception e) {
      return ProjectToolSupport.error(e.getMessage());
    }
  }

  private Map<String, Object> ref(Program p, Reference r, String d) {
    Address from = r.getFromAddress(), to = r.getToAddress();
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("direction", d);
    m.put("from", from.toString());
    m.put("to", to.toString());
    m.put("type", String.valueOf(r.getReferenceType()));
    Function ff = p.getFunctionManager().getFunctionContaining(from),
        tf = p.getFunctionManager().getFunctionContaining(to);
    if (ff != null) m.put("from_function", BatchQuerySupport.function(ff));
    if (tf != null) m.put("to_function", BatchQuerySupport.function(tf));
    m.put("from_symbols", BatchQuerySupport.symbolsAt(p, from));
    m.put("to_symbols", BatchQuerySupport.symbolsAt(p, to));
    m.put("symbol_limit", 32);
    m.put("from_symbols_truncated", p.getSymbolTable().getSymbols(from).length > 32);
    m.put("to_symbols_truncated", p.getSymbolTable().getSymbols(to).length > 32);
    return m;
  }
}
