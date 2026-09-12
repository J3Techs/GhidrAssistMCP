package ghidrassistmcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.*;
import ghidra.util.task.TaskMonitor;

public class XrefsBatchTool implements McpTool {
  @Override public Map<String, Object> getOutputSchema() { return BatchResultSchemas.xrefs(); }

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
            Map.of("type", "array", "minItems", 1, "maxItems", 1000, "items", Map.of("type", "string", "minLength", 1)),
            "direction",
            Map.of("type", "string", "enum", List.of("to", "from", "both"), "default", "both"),
            "per_address_limit",
            Map.of("type", "integer", "minimum", 0, "maximum", 1000, "default", 100),
            "reference_kind", Map.of("type", "string", "enum", List.of("all", "call", "jump", "data", "read", "write", "indirect", "flow")),
            "operand_index", Map.of("type", "integer", "minimum", -1, "maximum", 255),
            "external_only", Map.of("type", "boolean", "default", false),
            "max_scanned", Map.of("type", "integer", "minimum", 1, "maximum", 100000, "default", 10000)),
        List.of("addresses"),
        null,
        null,
        null);
  }

  public McpSchema.CallToolResult execute(Map<String, Object> a, Program p) {
    return read(a, p, TaskMonitor.DUMMY);
  }

  @Override public boolean isLongRunning() { return true; }
  @Override public McpSchema.CallToolResult execute(Map<String, Object> a, Program p,
      ghidrassistmcp.GhidrAssistMCPBackend backend, ghidrassistmcp.tasks.McpTask task) {
    return read(a, p, new ghidrassistmcp.tasks.McpTaskMonitor(task, 0, 100, "References"));
  }

  private McpSchema.CallToolResult read(Map<String, Object> a, Program p, TaskMonitor monitor) {
    try {
      if (p == null) return ProjectToolSupport.error("No program currently loaded");
      List<?> as =
          BatchQuerySupport.list(a.get("addresses"), "addresses", BatchQuerySupport.MAX_ROWS);
      String dir = a.getOrDefault("direction", "both").toString();
      if (!List.of("to", "from", "both").contains(dir))
        throw new IllegalArgumentException("invalid direction");
      int lim = BatchQuerySupport.integer(a, "per_address_limit", 100, 1000);
      String kind = a.getOrDefault("reference_kind", "all").toString();
      if (!List.of("all", "call", "jump", "data", "read", "write", "indirect", "flow").contains(kind))
        throw new IllegalArgumentException("Invalid reference_kind");
      Integer operand = null;
      if (a.containsKey("operand_index")) {
        Object value = a.get("operand_index");
        if (!(value instanceof Number n) || !Double.isFinite(n.doubleValue()) ||
            n.doubleValue() != n.longValue() || n.longValue() < -1 || n.longValue() > 255)
          throw new IllegalArgumentException("operand_index must be an integer in -1..255");
        operand = n.intValue();
      }
      int scanLimit = BatchQuerySupport.integer(a, "max_scanned", 10000, 100000);
      if (scanLimit == 0) throw new IllegalArgumentException("max_scanned must be positive");
      int[] scanned = {0};
      if ((long) lim * as.size() > 10000) throw new IllegalArgumentException("total xref limit exceeds 10000; reduce addresses or per_address_limit");
      List<Object> rows = new ArrayList<>();
      int errors = 0;
      for (Object o : as) {
        monitor.checkCancelled();
        Map<String, Object> row = new LinkedHashMap<>();
        try {
          Address ad = BatchQuerySupport.address(p, BatchQuerySupport.text(o, "address"));
          row.putAll(BatchQuerySupport.addr(ad));
          List<Object> x = new ArrayList<>();
          boolean truncated = false;
          if (dir.equals("to") || dir.equals("both")) {
            ReferenceIterator it = p.getReferenceManager().getReferencesTo(ad);
            truncated |= collect(p, it, "to", x, lim, kind, operand, Boolean.TRUE.equals(a.get("external_only")), scanned, scanLimit, monitor);
          }
          if (dir.equals("from") || dir.equals("both")) {
            truncated |= collect(p, Arrays.asList(p.getReferenceManager().getReferencesFrom(ad)).iterator(), "from", x, lim,
                kind, operand, Boolean.TRUE.equals(a.get("external_only")), scanned, scanLimit, monitor);
          }
          row.put("xrefs", x);
          row.put("truncated", truncated);
        } catch (ghidra.util.exception.CancelledException e) { throw e;
        } catch (Exception e) {
          errors++;
          row.put("error", e.getMessage());
        }
        rows.add(row);
      }
      boolean truncated = rows.stream().anyMatch(row -> Boolean.TRUE.equals(((Map<?, ?>) row).get("truncated")));
      return ProjectToolSupport.result(
          Map.of("results", rows, "count", rows.size(), "errors", errors, "scanned", scanned[0], "scan_limit", scanLimit, "truncated",
              truncated, "partial", errors > 0 || truncated), errors == rows.size());
    } catch (Exception e) {
      return ProjectToolSupport.error(e.getMessage());
    }
  }

  private boolean collect(Program p, Iterator<Reference> refs, String direction, List<Object> rows, int limit,
      String kind, Integer operand, boolean externalOnly, int[] scanned, int maxScanned, TaskMonitor monitor) throws Exception {
    while (refs.hasNext()) {
      monitor.checkCancelled();
      if (scanned[0] >= maxScanned) return true;
      Reference r = refs.next(); scanned[0]++;
      if (operand != null && operand != r.getOperandIndex()) continue;
      if (externalOnly && !r.isExternalReference()) continue;
      RefType t = r.getReferenceType();
      boolean matches = switch (kind) {
        case "call" -> t.isCall(); case "jump" -> t.isJump(); case "data" -> t.isData();
        case "read" -> t.isRead(); case "write" -> t.isWrite(); case "indirect" -> t.isIndirect();
        case "flow" -> t.isFlow(); default -> true;
      };
      if (!matches) continue;
      if (rows.size() >= limit) return true;
      rows.add(ref(p, r, direction));
    }
    return false;
  }

  private Map<String, Object> ref(Program p, Reference r, String d) {
    Address from = r.getFromAddress(), to = r.getToAddress();
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("direction", d);
    m.put("from", from.toString());
    m.put("to", to.toString());
    m.put("type", String.valueOf(r.getReferenceType()));
    m.put("from_space", from.getAddressSpace().getName()); m.put("to_space", to.getAddressSpace().getName());
    m.put("operand_index", r.getOperandIndex()); m.put("source", r.getSource().toString());
    m.put("primary", r.isPrimary()); m.put("external", r.isExternalReference());
    var type = r.getReferenceType();
    m.put("flow", Map.of("call", type.isCall(), "jump", type.isJump(), "read", type.isRead(),
        "write", type.isWrite(), "indirect", type.isIndirect(), "data", type.isData()));
    var symbol = p.getSymbolTable().getPrimarySymbol(to);
    if (symbol != null && symbol.isExternal()) {
      var location = p.getExternalManager().getExternalLocation(symbol);
      if (location != null) m.put("external_location", Map.of("library", location.getLibraryName(),
          "label", Objects.toString(location.getLabel(), ""), "original_name", Objects.toString(location.getOriginalImportedName(), ""),
          "address", Objects.toString(location.getAddress(), "")));
    }
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
