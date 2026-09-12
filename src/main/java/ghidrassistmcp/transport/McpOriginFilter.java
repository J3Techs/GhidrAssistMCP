package ghidrassistmcp.transport;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/** Validates browser origins against the configured listener, never the request Host header. */
public final class McpOriginFilter implements Filter {
    private static final Set<String> LOOPBACK = Set.of("localhost", "127.0.0.1", "::1", "[::1]");
    private final String bindHost;

    public McpOriginFilter(String bindHost) {
        this.bindHost = bindHost == null ? "" : bindHost.toLowerCase(Locale.ROOT);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest http = (HttpServletRequest) request;
        var origins = Collections.list(http.getHeaders("Origin"));
        if (origins.size() > 1 || (!origins.isEmpty()
                && !allows(origins.get(0), http.getScheme(), http.getLocalPort()))) {
            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, "Origin is not allowed");
            return;
        }
        chain.doFilter(request, response);
    }

    boolean allows(String origin, String scheme, int port) {
        if (origin == null) return true; // Native MCP clients usually have no Origin header.
        try {
            URI uri = URI.create(origin);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                    || uri.getRawFragment() != null || !uri.getRawPath().isEmpty()
                    || !scheme.equalsIgnoreCase(uri.getScheme())) return false;
            int originPort = uri.getPort() == -1 ? ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80) : uri.getPort();
            String originHost = uri.getHost().toLowerCase(Locale.ROOT);
            boolean sameHost = LOOPBACK.contains(bindHost) ? LOOPBACK.contains(originHost)
                : !bindHost.isEmpty() && !Set.of("0.0.0.0", "::", "[::]").contains(bindHost)
                    && bindHost.equals(originHost);
            return sameHost && originPort == port;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
