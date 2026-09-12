package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.resources.McpResource;
import org.junit.jupiter.api.Test;

class ResourceTargetSelectionTest {
    @Test void resourceSelectsEncodedNameRatherThanActiveProgram() {
        Program active = program("active"), target = program("target + name");
        var backend = backend(active, List.of(active, target));
        try {
            assertEquals("target + name", backend.readResource("ghidra://fixture/target%20+%20name"));
            assertThrows(IllegalArgumentException.class, () -> backend.readResource("ghidra://fixture/missing"));
        } finally { backend.getTaskManager().shutdown(); }
    }

    @Test void ambiguousResourceNameDoesNotFallBackToActiveProgram() {
        Program active = program("same");
        var backend = backend(active, List.of(active, program("same")));
        try { assertThrows(IllegalArgumentException.class, () -> backend.readResource("ghidra://fixture/same")); }
        finally { backend.getTaskManager().shutdown(); }
    }

    private static GhidrAssistMCPBackend backend(Program active, List<Program> programs) {
        var backend = new GhidrAssistMCPBackend() {
            @Override public Program getCurrentProgram() { return active; }
            @Override public List<Program> getAllOpenPrograms() { return programs; }
        };
        backend.getResourceRegistry().registerResource(new McpResource() {
            public String getName() { return "target_fixture"; }
            public String getUriPattern() { return "ghidra://fixture/{name}"; }
            public String getDescription() { return "Fixture"; }
            public String getMimeType() { return "text/plain"; }
            public boolean canHandle(String uri) { return uri.startsWith("ghidra://fixture/"); }
            public Map<String, String> extractParams(String uri) { return Map.of("name", uri.substring("ghidra://fixture/".length())); }
            public String readContent(Program program, Map<String, String> params) { return program.getName(); }
        });
        return backend;
    }

    private static Program program(String name) {
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(), new Class<?>[]{Program.class},
            (proxy, method, args) -> switch (method.getName()) {
                case "getName" -> name;
                case "addConsumer" -> true;
                case "isUsedBy" -> true;
                case "release" -> null;
                case "getDomainFile" -> null;
                case "isClosed" -> false;
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == args[0];
                default -> throw new UnsupportedOperationException(method.getName());
            });
    }
}
