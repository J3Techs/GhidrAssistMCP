package ghidrassistmcp.tools;

import java.util.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.ProgramIdentity;
import ghidrassistmcp.decompiler.DecompilerService;
import io.modelcontextprotocol.spec.McpSchema;

/** Bounded native facts, exposed as an optional representation of get_code. */
final class StructuredCode {
    private StructuredCode() {}
    static McpSchema.CallToolResult read(DecompilerService service, Map<String, Object> args,
            Program program, Function function, String format, TaskMonitor monitor) {
        try {
            int limit = positive(args, "max_items", 1000, 10000);
            int timeout = positive(args, "timeout_seconds", 30, 300);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("program", ProgramIdentity.describe(program));
            result.put("function", BatchQuerySupport.function(function));
            result.put("prototype", function.getPrototypeString(false, false));
            result.put("format", format); result.put("max_items", limit);
            if (format.equals("disassembly")) {
                var iterator = program.getListing().getInstructions(function.getBody(), true);
                List<Object> instructions = new ArrayList<>();
                while (iterator.hasNext() && instructions.size() < limit) {
                    monitor.checkCancelled(); Instruction i = iterator.next();
                    List<String> operands = new ArrayList<>();
                    for (int k = 0; k < i.getNumOperands(); k++) operands.add(i.getDefaultOperandRepresentation(k));
                    Map<String, Object> row = new LinkedHashMap<>(BatchQuerySupport.addr(i.getAddress()));
                    row.put("mnemonic", i.getMnemonicString()); row.put("operands", operands);
                    row.put("length", i.getLength()); row.put("flow_type", i.getFlowType().toString());
                    if (i.getFallThrough() != null) row.put("fallthrough", BatchQuerySupport.addr(i.getFallThrough()));
                    row.put("flows", Arrays.stream(i.getFlows()).map(BatchQuerySupport::addr).toList());
                    instructions.add(row);
                }
                result.put("instructions", instructions); result.put("truncated", iterator.hasNext());
                return ProjectToolSupport.result(result);
            }
            try (var session = service.open(program)) {
                DecompileResults decompiled = session.decompiler().decompileFunction(function, timeout, monitor);
                monitor.checkCancelled();
                if (!decompiled.decompileCompleted() || decompiled.getHighFunction() == null)
                    return ProjectToolSupport.error("Decompilation " + (decompiled.isTimedOut() ? "timed out" : "failed") + ": " + decompiled.getErrorMessage());
                HighFunction high = decompiled.getHighFunction();
                result.put("decompile_completed", true);
                String cText = decompiled.getDecompiledFunction() == null ? null : decompiled.getDecompiledFunction().getC();
                if (cText != null) {
                    int cMax = positive(args, "max_chars", 200000, 200000);
                    result.put("c", cText.length() <= cMax ? cText : cText.substring(0, cMax));
                    result.put("c_truncated", cText.length() > cMax);
                }
                result.put("diagnostic", Objects.toString(decompiled.getErrorMessage(), ""));
                result.put("basic_block_count", high.getBasicBlocks().size());
                List<Object> symbols = new ArrayList<>();
                var symbolIterator = high.getLocalSymbolMap().getSymbols();
                while (symbolIterator.hasNext() && symbols.size() < limit) {
                    monitor.checkCancelled(); var symbol = symbolIterator.next();
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("id", Long.toUnsignedString(symbol.getId())); row.put("name", symbol.getName());
                    row.put("type", symbol.getDataType().getPathName()); row.put("size", symbol.getSize());
                    row.put("parameter", symbol.isParameter()); row.put("storage", symbol.getStorage().toString());
                    row.put("type_locked", symbol.isTypeLocked()); row.put("name_locked", symbol.isNameLocked());
                    symbols.add(row);
                }
                result.put("variables", symbols); result.put("variables_truncated", symbolIterator.hasNext());
                List<Object> operations = new ArrayList<>();
                var ops = high.getPcodeOps();
                while (ops.hasNext() && operations.size() < limit) {
                    monitor.checkCancelled(); var op = ops.next();
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("address", BatchQuerySupport.addr(op.getSeqnum().getTarget()));
                    row.put("sequence", op.getSeqnum().getTime()); row.put("opcode", op.getMnemonic());
                    row.put("block", op.getParent() == null ? -1 : op.getParent().getIndex());
                    row.put("inputs", Arrays.stream(op.getInputs()).map(StructuredCode::varnode).toList());
                    if (op.getOutput() != null) row.put("output", varnode(op.getOutput()));
                    operations.add(row);
                }
                result.put("pcode", operations); result.put("pcode_truncated", ops.hasNext());
                result.put("pcode_stage", "decompiler_high");
                boolean tokenTruncated = false;
                if (Boolean.TRUE.equals(args.get("include_tokens"))) {
                    List<Object> tokens = new ArrayList<>();
                    var markup = decompiled.getCCodeMarkup();
                    if (markup != null) {
                        var iterator = markup.tokenIterator(true);
                        int chars = 0;
                        while (iterator.hasNext() && tokens.size() < limit) {
                            monitor.checkCancelled(); var token = iterator.next();
                            String text = Objects.toString(token.getText(), "");
                            if (chars + text.length() > 65536) { tokenTruncated = true; break; }
                            chars += text.length(); Map<String, Object> row = new LinkedHashMap<>();
                            row.put("text", text); row.put("kind", token.getClass().getSimpleName());
                            row.put("syntax_type", token.getSyntaxType());
                            if (token.getMinAddress() != null) row.put("min_address", BatchQuerySupport.addr(token.getMinAddress()));
                            if (token.getMaxAddress() != null) row.put("max_address", BatchQuerySupport.addr(token.getMaxAddress()));
                            tokens.add(row);
                        }
                        tokenTruncated |= iterator.hasNext();
                    }
                    result.put("tokens", tokens); result.put("tokens_truncated", tokenTruncated);
                }
                result.put("truncated", symbolIterator.hasNext() || ops.hasNext() || tokenTruncated);
                return ProjectToolSupport.result(result);
            }
        } catch (ghidra.util.exception.CancelledException e) {
            throw new java.util.concurrent.CancellationException("Code request cancelled");
        } catch (Exception e) { return ProjectToolSupport.error(e.getClass().getSimpleName() + ": " + e.getMessage()); }
    }
    private static Map<String, Object> varnode(Varnode value) {
        if (value == null) return Map.of("absent", true);
        return Map.of("address", BatchQuerySupport.addr(value.getAddress()), "size", value.getSize(),
            "constant", value.isConstant(), "register", value.isRegister(), "unique", value.isUnique());
    }
    static int positive(Map<String, Object> args, String key, int fallback, int max) {
        int result = BatchQuerySupport.integer(args, key, fallback, max);
        if (result == 0) throw new IllegalArgumentException(key + " must be positive");
        return result;
    }
}
