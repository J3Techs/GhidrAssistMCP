package ghidrassistmcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.*;

public class QueryAddressContextBatchTool implements McpTool {
  @Override public Map<String, Object> getOutputSchema() { return BatchResultSchemas.context(); }

  public String getName() {
    return "query_address_context_batch";
  }

  public String getDescription() {
    return "Batch read-only address context: bytes, function, symbols, data/instruction and xrefs.";
  }

  public McpSchema.JsonSchema getInputSchema() {
    return new McpSchema.JsonSchema(
        "object",
        Map.of(
            "addresses",
            Map.of("type", "array", "minItems", 1, "maxItems", 1000, "items", Map.of("type", "string", "minLength", 1)),
            "byte_length",
            Map.of("type", "integer", "minimum", 0, "maximum", 65536, "default", 16),
            "xref_limit",
            Map.of("type", "integer", "minimum", 0, "maximum", 1000, "default", 32)),
        List.of("addresses"),
        null,
        null,
        null);
  }

  public McpSchema.CallToolResult execute(Map<String, Object> a, Program p) {
    try {
      if (p == null) return ProjectToolSupport.error("No program currently loaded");
      List<?> in =
          BatchQuerySupport.list(a.get("addresses"), "addresses", BatchQuerySupport.MAX_ROWS);
      int n = BatchQuerySupport.integer(a, "byte_length", 16, 65536),
          xl = BatchQuerySupport.integer(a, "xref_limit", 32, 1000);
      if ((long) n * in.size() > BatchQuerySupport.MAX_BYTES)
        throw new IllegalArgumentException("total byte budget exceeded");
      if ((long) xl * in.size() > 10000) throw new IllegalArgumentException("total xref limit exceeds 10000; reduce addresses or xref_limit");
      List<Object> rows = new ArrayList<>();
      int errors = 0;
      for (Object o : in) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
          Address ad = BatchQuerySupport.address(p, BatchQuerySupport.text(o, "address"));
          r.putAll(BatchQuerySupport.addr(ad));
          Function f = p.getFunctionManager().getFunctionContaining(ad);
          if (f != null) r.put("function", BatchQuerySupport.function(f));
          r.put("symbols", BatchQuerySupport.symbolsAt(p, ad));
          Data d = p.getListing().getDataAt(ad);
          if (d != null)
            r.put(
                "data",
                Map.of(
                    "address",
                    d.getAddress().toString(),
                    "type",
                    d.getDataType().getPathName(),
                    "length",
                    d.getLength()));
          Instruction ins = p.getListing().getInstructionAt(ad);
          if (ins != null)
            r.put(
                "instruction",
                Map.of(
                    "address",
                    ins.getAddress().toString(),
                    "text",
                    ins.toString(),
                    "length",
                    ins.getLength()));
          r.put("bytes", BatchQuerySupport.bytes(p, ad, n));
          List<Object> xr = new ArrayList<>();
          ReferenceIterator it = p.getReferenceManager().getReferencesTo(ad);
          while (it.hasNext() && xr.size() < xl) {
            Reference q = it.next();
            xr.add(
                Map.of(
                    "direction",
                    "to",
                    "from",
                    q.getFromAddress().toString(),
                    "to",
                    q.getToAddress().toString(),
                    "type",
                    String.valueOf(q.getReferenceType())));
          }
          r.put("xrefs", xr);
          r.put("truncated", it.hasNext());
          r.put("symbol_limit", 32);
          r.put("symbols_truncated", p.getSymbolTable().getSymbols(ad).length > 32);
        } catch (Exception e) {
          errors++;
          r.put("error", e.getMessage());
        }
        rows.add(r);
      }
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("results", rows);
      out.put("count", rows.size());
      out.put("errors", errors);
      out.put("truncated", rows.stream().anyMatch(row -> Boolean.TRUE.equals(((Map<?, ?>) row).get("truncated"))));
      out.put("partial", errors > 0 || rows.stream().anyMatch(value -> {
        Map<?, ?> row = (Map<?, ?>) value;
        return Boolean.TRUE.equals(row.get("truncated")) || Boolean.TRUE.equals(row.get("symbols_truncated"))
            || row.get("bytes") instanceof Map<?, ?> bytes && Boolean.TRUE.equals(bytes.get("truncated"));
      }));
      return ProjectToolSupport.result(out, errors == rows.size());
    } catch (Exception e) {
      return ProjectToolSupport.error(e.getMessage());
    }
  }
}
