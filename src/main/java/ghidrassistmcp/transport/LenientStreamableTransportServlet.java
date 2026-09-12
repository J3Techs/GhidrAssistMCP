package ghidrassistmcp.transport;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Objects;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import io.modelcontextprotocol.server.transport.HttpServletStreamableServerTransportProvider;

/**
 * Compatibility shim for streamable HTTP MCP clients with stricter/older header behavior.
 */
public class LenientStreamableTransportServlet extends HttpServlet {

    private static final String ACCEPT = "Accept";

    private final HttpServletStreamableServerTransportProvider delegate;
    private final String mcpEndpoint;

    public LenientStreamableTransportServlet(
            HttpServletStreamableServerTransportProvider delegate,
            String mcpEndpoint) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.mcpEndpoint = Objects.requireNonNull(mcpEndpoint, "mcpEndpoint must not be null");
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpServletRequest wrappedReq = wrapRequest(req);
        // Session identity must come from this request. The SDK owns session validation.
        delegate.service(wrappedReq, resp);
    }

    @Override
    public void destroy() {
        delegate.destroy();
        super.destroy();
    }

    HttpServletRequest wrapRequest(HttpServletRequest request) {
        return new HttpServletRequestWrapper(request) {
            @Override
            public String getRequestURI() {
                String uri = super.getRequestURI();
                if (uri != null && uri.endsWith(mcpEndpoint + "/")) {
                    return uri.substring(0, uri.length() - 1);
                }
                return uri;
            }

            @Override
            public String getHeader(String name) {
                if (name == null) {
                    return super.getHeader(null);
                }
                if (ACCEPT.equalsIgnoreCase(name)) {
                    return normalizeAccept(super.getHeader(name));
                }
                return super.getHeader(name);
            }

            @Override
            public Enumeration<String> getHeaders(String name) {
                if (name != null && ACCEPT.equalsIgnoreCase(name)) {
                    return Collections.enumeration(Collections.singletonList(normalizeAccept(super.getHeader(name))));
                }
                return super.getHeaders(name);
            }
        };
    }

    private static String normalizeAccept(String original) {
        String value = original == null ? "" : original;
        String lower = value.toLowerCase(Locale.ROOT);
        boolean hasJson = lower.contains("application/json");
        boolean hasSse = lower.contains("text/event-stream");

        if (hasJson && hasSse) {
            return value;
        }

        StringBuilder sb = new StringBuilder(value.trim());
        if (sb.length() > 0) {
            sb.append(", ");
        }
        if (!hasJson) {
            sb.append("application/json");
            if (!hasSse) {
                sb.append(", ");
            }
        }
        if (!hasSse) {
            sb.append("text/event-stream");
        }
        return sb.toString();
    }
}
