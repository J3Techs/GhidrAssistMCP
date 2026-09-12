package ghidrassistmcp.tools;

import java.util.Map;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.decompiler.DecompilerService;
import io.modelcontextprotocol.spec.McpSchema;

/** Shared persistence path for the consolidated and legacy variable retype tools. */
final class VariableRetypeSupport {
    private VariableRetypeSupport() {}
    static McpSchema.CallToolResult execute(DecompilerService service, Map<String, Object> args,
            Program program, TaskMonitor monitor) {
        try {
            if (program == null) return ProjectToolSupport.error("No program currently loaded");
            String functionName = ProjectToolSupport.required(args, "function_name");
            String variableName = ProjectToolSupport.required(args, "variable_name");
            String typeName = ProjectToolSupport.required(args, "data_type");
            var function = FunctionLookup.findByQualifiedName(program, functionName);
            if (function == null) {
                var address = program.getAddressFactory().getAddress(functionName);
                if (address != null) function = program.getFunctionManager().getFunctionContaining(address);
            }
            if (function == null) return ProjectToolSupport.error("Function not found: " + functionName);
            var resolved = DataTypeResolver.resolve(program.getDataTypeManager(), typeName, null);
            DataType type = resolved.dataType;
            if (type == null) type = BuiltInDataTypeManager.getDataTypeManager().getDataType(typeName.startsWith("/") ? typeName : "/" + typeName);
            if (type == null) return ProjectToolSupport.error("Data type not found: " + typeName);
            if (program.getCurrentTransactionInfo() != null) return ProjectToolSupport.error("Program has an active transaction");
            monitor.checkCancelled();
            // Existing database locals/parameters have stable storage and can be updated directly.
            for (var variable : function.getAllVariables()) {
                if (!variableName.equals(variable.getName())) continue;
                int tx = program.startTransaction("Retype Variable");
                boolean commit = false;
                try {
                    variable.setDataType(type, SourceType.USER_DEFINED);
                    monitor.checkCancelled();
                    commit = true;
                    return success(functionName, variableName, type);
                } finally { program.endTransaction(tx, commit); }
            }
            // Decompiler-only locals first need their high symbol persisted to the database.
            try (var session = service.open(program)) {
                var decompiled = session.decompiler().decompileFunction(function, session.options().getDefaultTimeout(), monitor);
                monitor.checkCancelled();
                if (!decompiled.decompileCompleted() || decompiled.getHighFunction() == null)
                    return ProjectToolSupport.error("Decompilation failed: " + decompiled.getErrorMessage());
                HighSymbol found = null;
                var symbols = decompiled.getHighFunction().getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    var symbol = symbols.next();
                    if (variableName.equals(symbol.getName())) {
                        if (found != null) return ProjectToolSupport.error("Ambiguous variable name: " + variableName);
                        found = symbol;
                    }
                }
                if (found == null) return ProjectToolSupport.error("Variable not found: " + variableName);
                int tx = program.startTransaction("Retype Variable");
                boolean commit = false;
                try {
                    HighFunctionDBUtil.updateDBVariable(found, null, type, SourceType.USER_DEFINED);
                    monitor.checkCancelled();
                    commit = true;
                    return success(functionName, variableName, type);
                } finally { program.endTransaction(tx, commit); }
            }
        } catch (Exception e) { return ProjectToolSupport.error("Variable retype failed: " + e.getMessage()); }
    }
    private static McpSchema.CallToolResult success(String function, String variable, DataType type) {
        return ProjectToolSupport.result(Map.of("function", function, "variable", variable,
            "data_type", type.getPathName(), "changed", true, "saved", false));
    }
}
