/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.decompiler.DecompilerSession;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that sets the data type of a local variable within a function.
 */
public class SetLocalVariableTypeTool implements McpTool {

    private final DecompilerService decompilerService;

    public SetLocalVariableTypeTool(DecompilerService decompilerService) {
        this.decompilerService = decompilerService;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public String getName() {
        return "set_local_variable_type";
    }
    
    @Override
    public String getDescription() {
        return "Set the data type of a local variable within a function";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "function_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "variable_name", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "data_type", new McpSchema.JsonSchema("string", null, null, null, null, null)
            ),
            List.of("function_name", "variable_name", "data_type"), null, null, null);
    }
    
    @Override public boolean isLongRunning() { return true; }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return VariableRetypeSupport.execute(decompilerService, args, program, new ghidra.util.task.TaskMonitorAdapter(true));
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
            ghidrassistmcp.GhidrAssistMCPBackend backend, ghidrassistmcp.tasks.McpTask task) {
        return VariableRetypeSupport.execute(decompilerService, args, program,
            task == null ? new ghidra.util.task.TaskMonitorAdapter(true) : new ghidrassistmcp.tasks.McpTaskMonitor(task, 0, 100, "Retype Variable"));
    }
}
