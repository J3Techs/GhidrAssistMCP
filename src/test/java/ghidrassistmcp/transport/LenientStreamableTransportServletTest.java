package ghidrassistmcp.transport;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.*;
import java.util.concurrent.*;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.json.jackson2.JacksonMcpJsonMapper;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;
import jakarta.servlet.http.HttpServletRequest;
import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.spec.McpSchema;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;

class LenientStreamableTransportServletTest {
    @Test void strictDefaultPreservesClientAcceptHeader() {
        var provider = HttpServletStreamableServerTransportProvider.builder()
            .jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper())).mcpEndpoint("/mcp").build();
        var servlet = new LenientStreamableTransportServlet(provider, "/mcp");
        try {
            assertEquals("application/json", servlet.wrapRequest(request(null)).getHeader("Accept"));
        } finally { servlet.destroy(); }
    }

    @Test void realTransportInitializesIndependentClientsAndDoesNotRememberTheirHeaders() throws Exception {
        var provider = HttpServletStreamableServerTransportProvider.builder()
            .jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper())).mcpEndpoint("/mcp").build();
        var servlet = new LenientStreamableTransportServlet(provider, "/mcp", true);
        var mcp = McpServer.sync(provider).serverInfo("session-regression", "1.0")
            .capabilities(McpSchema.ServerCapabilities.builder().build()).build();
        var server = new Server();
        var connector = new ServerConnector(server);
        connector.setHost("127.0.0.1"); connector.setPort(0); server.addConnector(connector);
        var context = new ServletContextHandler();
        context.setContextPath("/"); context.addServlet(new ServletHolder(servlet), "/mcp/*"); server.setHandler(context);
        try (var client = HttpClient.newHttpClient()) {
            server.start();
            URI endpoint = URI.create("http://127.0.0.1:" + connector.getLocalPort() + "/mcp/");
            List<CompletableFuture<HttpResponse<String>>> pending = new ArrayList<>();
            for (String name : List.of("client-a", "client-b")) {
                String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"" + name + "\",\"version\":\"1\"}}}";
                pending.add(client.sendAsync(HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json").header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString()));
            }
            Set<String> sessions = new HashSet<>();
            for (var response : pending) {
                var initialized = response.get(15, TimeUnit.SECONDS);
                assertEquals(200, initialized.statusCode(), initialized.body());
                String id = initialized.headers().firstValue("Mcp-Session-Id").orElseThrow();
                assertTrue(sessions.add(id), "Each initialize must create its own session");
                assertEquals(id, servlet.wrapRequest(request(id)).getHeader("Mcp-Session-Id"));
            }
            // After actual response headers were issued, the shim must still invent no identity.
            assertNull(servlet.wrapRequest(request(null)).getHeader("Mcp-Session-Id"));
            assertFalse(servlet.wrapRequest(request(null)).getHeaders("Mcp-Session-Id").hasMoreElements());
        } finally { mcp.close(); server.stop(); }
    }

    @Test void concurrentRequestWrappersPreserveOnlyExplicitSessionHeaders() throws Exception {
        var provider = HttpServletStreamableServerTransportProvider.builder()
            .jsonMapper(new JacksonMcpJsonMapper(new ObjectMapper())).mcpEndpoint("/mcp").build();
        var servlet = new LenientStreamableTransportServlet(provider, "/mcp", true);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Callable<Void>> checks = new ArrayList<>();
            for (String id : List.of("client-a", "client-b")) checks.add(() -> {
                var wrapped = servlet.wrapRequest(request(id));
                assertEquals(id, wrapped.getHeader("Mcp-Session-Id"));
                assertEquals(List.of(id), Collections.list(wrapped.getHeaders("Mcp-Session-Id")));
                var missing = servlet.wrapRequest(request(null));
                assertNull(missing.getHeader("Mcp-Session-Id"));
                assertFalse(missing.getHeaders("Mcp-Session-Id").hasMoreElements());
                assertEquals("/mcp", wrapped.getRequestURI());
                assertTrue(wrapped.getHeader("Accept").contains("application/json"));
                assertTrue(wrapped.getHeader("Accept").contains("text/event-stream"));
                return null;
            });
            for (Future<Void> check : executor.invokeAll(checks)) check.get();
        } finally { servlet.destroy(); }
    }

    private HttpServletRequest request(String session) {
        return (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
            (p,m,a) -> switch(m.getName()) {
                case "getRequestURI" -> "/mcp/";
                case "getHeader" -> "Mcp-Session-Id".equalsIgnoreCase((String)a[0]) ? session : "application/json";
                case "getHeaders" -> session == null ? Collections.emptyEnumeration() : Collections.enumeration(List.of(session));
                default -> null;
            });
    }
}
