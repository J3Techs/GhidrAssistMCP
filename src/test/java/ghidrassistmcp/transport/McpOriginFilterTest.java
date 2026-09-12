package ghidrassistmcp.transport;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

class McpOriginFilterTest {
    @Test void acceptsNativeClientsAndExactLocalOrigins() {
        var filter = new McpOriginFilter("127.0.0.1");
        assertTrue(filter.allows(null, "http", 8080));
        assertTrue(filter.allows("http://localhost:8080", "http", 8080));
        assertTrue(filter.allows("http://[::1]:8080", "http", 8080));
        assertTrue(filter.allows("http://127.0.0.1", "http", 80));
        assertFalse(filter.allows("http://localhost:8081", "http", 8080));
        assertFalse(filter.allows("https://localhost:8080", "http", 8080));
    }

    @Test void rejectsOpaqueMalformedAndNonMatchingOrigins() {
        var filter = new McpOriginFilter("127.0.0.1");
        for (String origin : List.of("null", "", "https://example.com", "http://localhost:8080/",
                "http://localhost:8080/path", "http://user@localhost:8080", "http://localhost:8080?x=1",
                "http://localhost:8080#fragment", "http://localhost:8080 http://example.com")) {
            assertFalse(filter.allows(origin, "http", 8080), origin);
        }
        assertFalse(new McpOriginFilter("0.0.0.0").allows("http://0.0.0.0:8080", "http", 8080));
        assertTrue(new McpOriginFilter("analysis.local").allows("http://analysis.local:8080", "http", 8080));
    }

    @Test void filterRejectsRepeatedOriginsBeforeInvokingApplication() throws Exception {
        var filter = new McpOriginFilter("127.0.0.1");
        var status = new AtomicInteger();
        var invoked = new AtomicBoolean();
        var request = (HttpServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[] {HttpServletRequest.class}, (p, m, a) -> switch (m.getName()) {
                case "getHeaders" -> Collections.enumeration(List.of("http://localhost:8080", "http://localhost:8080"));
                case "getScheme" -> "http";
                case "getLocalPort" -> 8080;
                default -> null;
            });
        var response = (HttpServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[] {HttpServletResponse.class}, (p, m, a) -> {
                if (m.getName().equals("sendError")) status.set((Integer) a[0]);
                return null;
            });
        filter.doFilter(request, response, (req, resp) -> invoked.set(true));
        assertEquals(403, status.get());
        assertFalse(invoked.get());
    }
}
