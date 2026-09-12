/* 
 * 
 */
package ghidrassistmcp;

import java.time.Duration;
import java.util.List;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.Map;
import java.util.function.BiFunction;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import jakarta.servlet.DispatcherType;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpSyncServerExchange;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpError;
import io.modelcontextprotocol.spec.McpServerTransportProviderBase;
import io.modelcontextprotocol.server.transport.HttpServletSseServerTransportProvider;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import io.modelcontextprotocol.spec.McpSchema;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.resources.McpResource;
import ghidrassistmcp.transport.LenientStreamableTransportServlet;
import ghidrassistmcp.transport.McpOriginFilter;

/**
 * Refactored MCP Server implementation that uses the backend architecture.
 * This class handles HTTP transport and delegates business logic to McpBackend.
 */
public class GhidrAssistMCPServer {
    
    private final McpBackend backend;
    private volatile GhidrAssistMCPProvider provider;
    private Server jettyServer;
    private final List<McpSyncServer> protocolServers = new ArrayList<>();
    private final List<McpServerTransportProviderBase> unownedTransports = new ArrayList<>();
    private final String host;
    private final int port;
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend) {
        this(host, port, backend, null);
    }

    public void setProvider(GhidrAssistMCPProvider provider) { this.provider = provider; }
    
    public GhidrAssistMCPServer(String host, int port, McpBackend backend, GhidrAssistMCPProvider provider) {
        this.host = host;
        this.port = port;
        this.backend = backend;
        this.provider = provider;
    }
    
    public synchronized void start() throws Exception {
        if (jettyServer != null) throw new IllegalStateException("Server already started; stop it before restarting");
        Msg.info(this, "Starting MCP Server initialization...");
        
        try {
            String bindHost = checkedBindHost(host, Boolean.getBoolean("ghidrassistmcp.transport.allowRemote"));
            // Create Jetty server
            Msg.info(this, "Creating Jetty server on port " + port);
            jettyServer = new Server();
            
            ServerConnector connector = new ServerConnector(jettyServer);
            connector.setHost(bindHost);
            connector.setPort(port);
            jettyServer.addConnector(connector);

            // Create servlet context
            Msg.info(this, "Setting up servlet context");
            ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
            context.setContextPath("/");
            FilterHolder originFilter = new FilterHolder(new McpOriginFilter(host));
            originFilter.setAsyncSupported(true);
            context.addFilter(originFilter, "/*", EnumSet.of(DispatcherType.REQUEST));
            jettyServer.setHandler(context);
            
            // Create MCP transport provider using custom ObjectMapper that ignores unknown properties
            Msg.info(this, "Creating MCP transport provider");
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            JacksonMcpJsonMapper mapper = new JacksonMcpJsonMapper(objectMapper);
            String messageEndpoint = "/message";
            String mcpEndpoint = "/mcp";

            HttpServletSseServerTransportProvider sseTransportProvider =
                HttpServletSseServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .messageEndpoint(messageEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .maxRequestSize(16 * 1024 * 1024)
                    .build();
            unownedTransports.add(sseTransportProvider);

            HttpServletStreamableServerTransportProvider streamableTransportProvider =
                HttpServletStreamableServerTransportProvider.builder()
                    .jsonMapper(mapper)
                    .mcpEndpoint(mcpEndpoint)
                    .keepAliveInterval(Duration.ofSeconds(15))
                    .maxRequestSize(16 * 1024 * 1024)
                    .build();
            unownedTransports.add(streamableTransportProvider);

            // Build MCP server using backend for configuration
            Msg.info(this, "Building MCP server with backend tools");
            var sseServerBuilder = McpServer.sync(sseTransportProvider)
                .serverInfo(backend.getServerInfo())
                .instructions(backend.getInstructions())
                .capabilities(backend.getCapabilities());

            var streamableServerBuilder = McpServer.sync(streamableTransportProvider)
                .serverInfo(backend.getServerInfo())
                .instructions(backend.getInstructions())
                .capabilities(backend.getCapabilities());

            // Register each tool individually with its own handler
            for (McpSchema.Tool toolSchema : backend.getAvailableTools()) {
                String toolName = toolSchema.name();
                BiFunction<McpSyncServerExchange, McpSchema.CallToolRequest, McpSchema.CallToolResult> toolHandler =
                    (exchange, request) -> {
                        // The backend now handles all logging through event listeners
                        Map<String, Object> params = request.arguments();
                        Object progressToken = request.meta() == null ? null : request.meta().get("progressToken");
                        McpRequestContext.ProgressReporter progress = validProgressToken(progressToken)
                            ? (value, total, message) -> exchange.progressNotification(
                                new McpSchema.ProgressNotification(progressToken, value, total, message))
                            : null;
                        return McpRequestContext.callWithProgress(progress,
                            () -> McpResultContent.withJsonFallback(backend.callTool(toolName, params)));
                    };

                sseServerBuilder.toolCall(toolSchema, toolHandler);
                streamableServerBuilder.toolCall(toolSchema, toolHandler);
                Msg.info(this, "Registered tool with MCP server: " + toolName);
            }

            // Register MCP resources and prompts if backend supports them
            if (backend instanceof GhidrAssistMCPBackend) {
                GhidrAssistMCPBackend ghidraBackend = (GhidrAssistMCPBackend) backend;
                registerResources(sseServerBuilder, streamableServerBuilder, ghidraBackend);
                registerPrompts(sseServerBuilder, streamableServerBuilder, ghidraBackend);
            }

            protocolServers.add(sseServerBuilder.build());
            unownedTransports.remove(sseTransportProvider);
            protocolServers.add(streamableServerBuilder.build());
            unownedTransports.remove(streamableTransportProvider);
            
            // Register MCP servlet - use root path since transport provider handles routing internally
            Msg.info(this, "Registering MCP servlet");
            
            try {
                ServletHolder mcpSseServletHolder = new ServletHolder("mcp-sse-transport", sseTransportProvider);
                mcpSseServletHolder.setAsyncSupported(true);
                context.addServlet(mcpSseServletHolder, "/sse");
                context.addServlet(mcpSseServletHolder, messageEndpoint);

                LenientStreamableTransportServlet lenientStreamableServlet =
                    new LenientStreamableTransportServlet(streamableTransportProvider, mcpEndpoint,
                        Boolean.getBoolean("ghidrassistmcp.transport.lenientAccept"));
                ServletHolder mcpStreamableServletHolder = new ServletHolder("mcp-streamable-transport", lenientStreamableServlet);
                mcpStreamableServletHolder.setAsyncSupported(true);
                context.addServlet(mcpStreamableServletHolder, "/mcp");
                context.addServlet(mcpStreamableServletHolder, "/mcp/*");
                Msg.info(this, "Registered MCP SSE servlet mapping: /sse and " + messageEndpoint);
                Msg.info(this, "Registered MCP Streamable servlet mapping: /mcp and /mcp/*");
                
                // Log configuration
                Msg.info(this, "Transport provider class: " + sseTransportProvider.getClass().getName());
                Msg.info(this, "Message endpoint configured as: " + messageEndpoint);
                Msg.info(this, "SSE endpoint will be: /sse (default)");
                Msg.info(this, "Expected client URLs:");
                Msg.info(this, "  SSE: http://" + host + ":" + port + "/sse");
                Msg.info(this, "  Messages: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "Streamable HTTP transport provider class: " + streamableTransportProvider.getClass().getName());
                Msg.info(this, "Streamable MCP endpoint: http://" + host + ":" + port + mcpEndpoint);
                
            } catch (Exception e) {
                throw new IllegalStateException("Failed to register MCP servlet", e);
            }
            
            // Start Jetty server
            Msg.info(this, "Starting Jetty server...");
            jettyServer.start();
            
            // Verify server is listening
            if (jettyServer.isStarted()) {
                Msg.info(this, "GhidrAssistMCP Server successfully started on port " + port);
                Msg.info(this, "MCP SSE endpoint: http://" + host + ":" + port + "/sse");
                Msg.info(this, "MCP message endpoint: http://" + host + ":" + port + messageEndpoint);
                Msg.info(this, "MCP Streamable endpoint: http://" + host + ":" + port + mcpEndpoint);
                Msg.info(this, "Server state: " + jettyServer.getState());
                
                // Log all registered servlets
                var servletHandler = context.getServletHandler();
                var servletMappings = servletHandler.getServletMappings();
                Msg.info(this, "Registered servlet mappings:");
                for (var mapping : servletMappings) {
                    Msg.info(this, "  " + mapping.getServletName() + " -> " + String.join(", ", mapping.getPathSpecs()));
                }
                
                // Log server startup to UI
            var activeProvider = provider;
            if (activeProvider != null) {
                activeProvider.logSession("Jetty server listening on port " + port);
                activeProvider.logSession("Registered " + backend.getAvailableTools().size() + " MCP tools");
                activeProvider.logSession("Ready for MCP client connections");
                }
            } else {
                Msg.error(this, "Failed to start Jetty server - server not in started state");
            }
            
        } catch (Exception e) {
            Msg.error(this, "Exception during MCP Server startup: " + e.getMessage(), e);
            try { stop(); } catch (Exception cleanup) { e.addSuppressed(cleanup); }
            throw e;
        }
    }

    public synchronized void stop() throws Exception {
        Exception failure = null;
        for (McpSyncServer server : protocolServers) {
            try { server.getAsyncServer().closeGracefully().block(Duration.ofSeconds(5)); }
            catch (Exception e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
        }
        protocolServers.clear();
        for (McpServerTransportProviderBase transport : unownedTransports) {
            try { transport.closeGracefully().block(Duration.ofSeconds(5)); }
            catch (Exception e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
        }
        unownedTransports.clear();
        if (jettyServer != null) {
            try { jettyServer.stop(); }
            catch (Exception e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
            finally { jettyServer = null; }
        }
        if (failure != null) throw failure;
        Msg.info(this, "GhidrAssistMCP Server stopped");
    }

    /**
     * Check if the underlying Jetty server is running.
     */
    public synchronized boolean isRunning() {
        return jettyServer != null && jettyServer.isRunning();
    }

    /**
     * Get the current Jetty server state string for diagnostics.
     */
    public synchronized String getState() {
        return jettyServer != null ? jettyServer.getState() : "null";
    }

    static String checkedBindHost(String host, boolean allowRemote) throws java.net.UnknownHostException {
        if (host == null || host.isBlank()) throw new IllegalArgumentException("Explicit MCP bind host required");
        var address = java.net.InetAddress.getByName(host);
        if (!allowRemote && !address.isLoopbackAddress())
            throw new IllegalArgumentException("MCP defaults to trusted local clients; non-loopback binding requires -Dghidrassistmcp.transport.allowRemote=true and an externally secured deployment");
        return address.getHostAddress();
    }

    /** Actual listener port, including an OS-assigned port when configured with zero. */
    public synchronized int getLocalPort() {
        if (jettyServer == null || jettyServer.getConnectors().length == 0) return -1;
        return ((ServerConnector) jettyServer.getConnectors()[0]).getLocalPort();
    }
    
    public void setCurrentProgram(Program program) {
        backend.onProgramActivated(program);
    }

    /**
     * Register MCP prompts with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerPrompts(McpServer.SyncSpecification sseServerBuilder,
                                  McpServer.SyncSpecification streamableServerBuilder,
                                  GhidrAssistMCPBackend ghidraBackend) {
        try {
            List<McpPrompt> prompts = ghidraBackend.getAvailablePrompts().stream()
                .sorted(Comparator.comparing(McpPrompt::getName)).toList();
            java.util.List<McpServerFeatures.SyncPromptSpecification> promptSpecs = new java.util.ArrayList<>();

            for (McpPrompt prompt : prompts) {
                // Create McpSchema.Prompt for each prompt
                McpSchema.Prompt mcpPrompt = new McpSchema.Prompt(
                    prompt.getName(),
                    prompt.getDescription(),
                    prompt.getArguments()
                );

                // Create handler for getting the prompt
                BiFunction<McpSyncServerExchange, McpSchema.GetPromptRequest, McpSchema.GetPromptResult> promptHandler =
                    (exchange, request) -> {
                        Map<String, Object> rawArgs = request.arguments();
                        Map<String, String> args = new java.util.HashMap<>();
                        if (rawArgs != null) {
                            for (Map.Entry<String, Object> entry : rawArgs.entrySet()) {
                                args.put(entry.getKey(), entry.getValue() != null ? entry.getValue().toString() : null);
                            }
                        }
                        return ghidraBackend.withProgramRequest(program -> prompt.generatePrompt(args, program));
                    };

                // Create specification
                McpServerFeatures.SyncPromptSpecification spec =
                    new McpServerFeatures.SyncPromptSpecification(mcpPrompt, promptHandler);
                promptSpecs.add(spec);
                Msg.info(this, "Prepared prompt for registration: " + prompt.getName());
            }

            // Register all prompts with both builders
            if (!promptSpecs.isEmpty()) {
                sseServerBuilder.prompts(promptSpecs);
                streamableServerBuilder.prompts(promptSpecs);
                Msg.info(this, "Registered " + promptSpecs.size() + " MCP prompts");
            }

        } catch (Exception e) {
            throw new IllegalStateException("Failed to register MCP prompts", e);
        }
    }

    /**
     * Register MCP resources with the server builders.
     */
    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void registerResources(McpServer.SyncSpecification sseServerBuilder,
                                   McpServer.SyncSpecification streamableServerBuilder,
                                   GhidrAssistMCPBackend ghidraBackend) {
        try {
            registerResourceSpecifications(sseServerBuilder, ghidraBackend.getAvailableResources(), ghidraBackend::readResource);
            registerResourceSpecifications(streamableServerBuilder, ghidraBackend.getAvailableResources(), ghidraBackend::readResource);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to register MCP resources", e);
        }
    }
    /** Register URI templates separately from concrete resources so discovery remains truthful. */
    static void registerResourceSpecifications(McpServer.SyncSpecification<?> builder, List<McpResource> resources,
            java.util.function.Function<String, String> reader) {
        for (McpResource resource : resources.stream().sorted(Comparator.comparing(McpResource::getName)).toList()) {
            BiFunction<McpSyncServerExchange, McpSchema.ReadResourceRequest, McpSchema.ReadResourceResult> handler =
                (exchange, request) -> readResourceResult(resource, request.uri(), reader);
            if (resource.getUriPattern().contains("{")) {
                McpSchema.ResourceTemplate template = McpSchema.ResourceTemplate.builder()
                    .uriTemplate(resource.getUriPattern()).name(resource.getName())
                    .description(resource.getDescription()).mimeType(resource.getMimeType()).build();
                builder.resourceTemplates(new McpServerFeatures.SyncResourceTemplateSpecification(template, handler));
            } else {
                McpSchema.Resource definition = McpSchema.Resource.builder()
                    .uri(resource.getUriPattern()).name(resource.getName())
                    .description(resource.getDescription()).mimeType(resource.getMimeType()).build();
                builder.resources(new McpServerFeatures.SyncResourceSpecification(definition, handler));
            }
        }
    }

    private static boolean validProgressToken(Object token) {
        if (token instanceof String) return true;
        if (!(token instanceof Number)) return false;
        try { return new java.math.BigDecimal(token.toString()).stripTrailingZeros().scale() <= 0; }
        catch (NumberFormatException e) { return false; }
    }

    static McpSchema.ReadResourceResult readResourceResult(McpResource resource, String uri,
            java.util.function.Function<String, String> reader) {
        final String content;
        try { content = reader.apply(uri); }
        catch (ProgramIdentity.NotOpenException e) { throw McpError.RESOURCE_NOT_FOUND.apply(uri); }
        catch (IllegalArgumentException e) {
            throw McpError.builder(McpSchema.ErrorCodes.INVALID_PARAMS).message(e.getMessage()).build();
        }
        if (content == null) throw McpError.RESOURCE_NOT_FOUND.apply(uri);
        return new McpSchema.ReadResourceResult(List.of(new McpSchema.TextResourceContents(uri, resource.getMimeType(), content)));
    }

}



