package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ghidra.util.task.TaskMonitor;

/**
 * Opt-in native BSim backend lifecycle test.
 *
 * The URLs must identify disposable repositories on a test-only PostgreSQL or
 * Elasticsearch BSim service. This test never starts, provisions, or drops a
 * service; it creates and drops only the repository named by the supplied URL.
 */
@Tag("external")
class BsimExternalBackendLifecycleTest {
    @Test
    void postgresLifecycle(@TempDir Path temporary) throws Exception {
        runLifecycle("BSIM_TEST_POSTGRES_URL", temporary);
    }

    @Test
    void elasticLifecycle(@TempDir Path temporary) throws Exception {
        runLifecycle("BSIM_TEST_ELASTIC_URL", temporary);
    }

    private static void runLifecycle(String variable, Path temporary) throws Exception {
        Assumptions.assumeTrue("1".equals(System.getenv("BSIM_RUN_EXTERNAL_TESTS")),
            "Set BSIM_RUN_EXTERNAL_TESTS=1 to enable native backend tests");
        String url = System.getenv(variable);
        Assumptions.assumeTrue(url != null && !url.isBlank(),
            "Set " + variable + " to a disposable BSim URL");

        try (BsimContext context = new BsimContext(null, null,
            new BsimConnections(temporary.resolve("settings")), temporary, null)) {
        Map<String, Object> target = Map.of("database_url", url);
        Map<String, Object> created = operation("create_database").handler().execute(context,
            Map.of("database_url", url, "template",
                System.getenv().getOrDefault("BSIM_TEST_TEMPLATE", "medium_64.xml"),
                "name", "MCP disposable test"), TaskMonitor.DUMMY);
        assertFalse(created.isEmpty());
        Map<String, Object> info = operation("database_info").handler().execute(
            context, target, TaskMonitor.DUMMY);
        assertEquals("MCP disposable test", info.get("name"));
        operation("update_database").handler().execute(context,
            Map.of("database_url", url, "description", "native lifecycle test"),
            TaskMonitor.DUMMY);
        operation("maintain_database").handler().execute(context,
            Map.of("database_url", url, "drop_index", true, "rebuild_index", true, "prewarm", true),
            TaskMonitor.DUMMY);
        Map<String, Object> dropped = operation("drop_database").handler().execute(context,
            Map.of("database_url", url, "confirm", true), TaskMonitor.DUMMY);
        assertEquals(true, dropped.get("dropped"));
        }
    }

    private static BsimOperation operation(String name) {
        return BsimDatabaseOperations.operations().stream()
            .filter(operation -> operation.name().equals(name)).findFirst().orElseThrow();
    }
}
