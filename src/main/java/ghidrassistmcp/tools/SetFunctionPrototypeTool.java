/* 
 * 
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;


import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.decompiler.DecompilerService;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that sets a function's prototype/signature.
 */
public class SetFunctionPrototypeTool implements McpTool {
    private final DecompilerService decompilerService;

    public SetFunctionPrototypeTool() { this(null); }
    public SetFunctionPrototypeTool(DecompilerService decompilerService) { this.decompilerService = decompilerService; }

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
        return "set_function_prototype";
    }
    
    @Override
    public String getDescription() {
        return "Set a function signature using native name-preservation rules; a default-origin name may change. Inspect stored_prototype and function_entry; return_code=true includes bounded decompilation after commit.";
    }
    
    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", 
            Map.of(
                "function_address", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "prototype", new McpSchema.JsonSchema("string", null, null, null, null, null),
                "return_code", new McpSchema.JsonSchema("boolean", null, null, null, null, null),
                "max_chars", new McpSchema.JsonSchema("integer", null, null, null, null, null),
                "verification_timeout_seconds", new McpSchema.JsonSchema("integer", null, null, null, null, null)
            ),
            List.of("function_address", "prototype"), null, null, null);
    }
    
    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // Fallback for when backend reference is not available
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("No program currently loaded")
                .build();
        }
        String optionError = PostMutationCode.validateOptions(arguments);
        if (optionError != null) return ProjectToolSupport.error(optionError);

        String functionAddrStr = (String) arguments.get("function_address");
        String prototype = (String) arguments.get("prototype");

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("function_address parameter is required")
                .build();
        }

        if (prototype == null || prototype.isEmpty()) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("prototype parameter is required")
                .build();
        }

        // Use proper prototype setting with transaction handling
        PrototypeResult result = setFunctionPrototype(currentProgram, functionAddrStr, prototype);

        if (!result.success || !Boolean.TRUE.equals(arguments.get("return_code")))
            return McpSchema.CallToolResult.builder().isError(!result.success).addTextContent(result.success ?
                "Successfully set function prototype: " + result.storedPrototype :
                "Failed to set function prototype: " + result.errorMessage).build();
        return PostMutationCode.result(currentProgram, result.function, result.storedPrototype,
            decompilerService, arguments);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        // This tool doesn't need UI context, so just delegate to the base implementation
        return execute(arguments, currentProgram);
    }
    
    /**
     * Result class for prototype operations
     */
    private static class PrototypeResult {
        final boolean success;
        final String errorMessage;
        final Function function;
        final String storedPrototype;
        
        PrototypeResult(boolean success, String errorMessage) { this(success, errorMessage, null, null); }
        PrototypeResult(boolean success, String errorMessage, Function function, String storedPrototype) {
            this.success = success;
            this.errorMessage = errorMessage;
            this.function = function;
            this.storedPrototype = storedPrototype;
        }
    }
    
    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(Program program, String functionAddrStr, String prototype) {
        // Input validation
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        Function function;
        try { function = FunctionLookup.resolve(program, functionAddrStr); }
        catch (Exception e) { return new PrototypeResult(false, e.getMessage()); }
        if (function == null) return new PrototypeResult(false, "Function not found: " + functionAddrStr);

        try {
            // This is a database command, not a UI operation. Keep execution on the
            // caller that owns the mutation guard instead of waiting for the EDT.
            applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage);
        } catch (Exception e) {
            String msg = "Failed to set function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        String stored = function == null ? null : function.getPrototypeString(false, false);
        return new PrototypeResult(success.get(), errorMessage.toString(), function, stored);
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Function func = FunctionLookup.resolve(program, functionAddrStr);
            Address addr = func == null ? null : func.getEntryPoint();
            if (func == null) {
                String msg = "Could not find function: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Use proper function signature parsing and application
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }
    
    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Create function signature parser
            // Note: Since we don't have access to the tool here, we'll create parser without DataTypeManagerService
            FunctionSignatureParser parser = new FunctionSignatureParser(dtm, null);

            // Parse the prototype into a function signature
            FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype: " + prototype;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                addPrototypeComment(program, program.getFunctionManager().getFunctionAt(addr), prototype);
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }
    
    /**
     * Add prototype as a comment for reference
     */
    private void addPrototypeComment(Program program, Function function, String prototype) {
        // Called only inside the signature transaction; failures must roll it back.
        String currentComment = function.getComment();
        String newComment = "Applied prototype: " + prototype;
        if (currentComment != null && currentComment.lines().noneMatch(newComment::equals)) {
            newComment = currentComment + "\n" + newComment;
        } else if (currentComment != null && !currentComment.isEmpty()) return;
        function.setComment(newComment);
    }
    
}
