package ghidrassistmcp;

import java.util.Map;
import java.util.Objects;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/** A legacy public name for an existing tool, preserving its execution contract. */
final class ToolAlias implements McpTool {
    private final String name;
    private final McpTool delegate;

    ToolAlias(String name, McpTool delegate) {
        this.name = Objects.requireNonNull(name);
        this.delegate = Objects.requireNonNull(delegate);
    }

    @Override public String getName() { return name; }
    @Override public String getDescription() {
        return "Compatibility alias for " + delegate.getName() + ". " + delegate.getDescription();
    }
    @Override public McpSchema.JsonSchema getInputSchema() { return delegate.getInputSchema(); }
    @Override public Map<String, Object> getInputSchemaMap() { return delegate.getInputSchemaMap(); }
    @Override public Map<String, Object> getOutputSchema() { return delegate.getOutputSchema(); }
    @Override public boolean isReadOnly() { return delegate.isReadOnly(); }
    @Override public boolean isDestructive() { return delegate.isDestructive(); }
    @Override public boolean isIdempotent() { return delegate.isIdempotent(); }
    @Override public boolean isOpenWorld() { return delegate.isOpenWorld(); }
    @Override public boolean isLongRunning() { return delegate.isLongRunning(); }
    @Override public boolean isCacheable() { return delegate.isCacheable(); }

    @Override
    public String getCacheDiscriminator(Map<String, Object> arguments, Program program,
                                       GhidrAssistMCPBackend backend) {
        return delegate.getCacheDiscriminator(arguments, program, backend);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program) {
        return delegate.execute(arguments, program);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
                                           GhidrAssistMCPBackend backend) {
        return delegate.execute(arguments, program, backend);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program program,
                                           GhidrAssistMCPBackend backend, McpTask task) {
        return delegate.execute(arguments, program, backend, task);
    }
}
