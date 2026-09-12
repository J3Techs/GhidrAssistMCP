package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.task.TaskMonitor;

/** Uses only a disposable H2 BSim file; no server or external service is contacted. */
class BsimDatabaseOperationsTest {
    @Test
    void lifecycleSchemasUseStructuredPropertyMaps() {
        for (BsimOperation operation : BsimDatabaseOperations.operations()) {
            operation.properties().values().forEach(value -> assertTrue(value instanceof Map,
                () -> operation.name() + " has non-schema property: " + value));
        }
    }

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.install.dir"))),
                new HeadlessGhidraApplicationConfiguration());
        }
    }

    @Test
    void h2CreateInfoUpdateAndDropUseStockProtocol(@TempDir Path temporary) throws Exception {
        Path settings = temporary.resolve("settings");
        Path databaseFile = temporary.resolve("fixture");
        BsimConnections connections = new BsimConnections(settings);
        try (BsimContext context = new BsimContext(null, null, connections, temporary, null)) {
        String url = databaseFile.toUri().toString();
        Map<String, Object> target = Map.of("database_url", url);

        BsimOperation create = operation("create_database");
        Map<String, Object> created = create.handler().execute(context,
            Map.of("database_url", url, "template", "medium_64.xml",
                "name", "Disposable", "owner", "test"), TaskMonitor.DUMMY);
        assertEquals("Disposable", created.get("name"));

        Map<String, Object> info = operation("database_info").handler().execute(
            context, target, TaskMonitor.DUMMY);
        assertEquals("Disposable", info.get("name"));
        assertEquals(true, info.containsKey("layout_version"));
        assertEquals("Ready", info.get("status"));

        Map<String, Object> updated = operation("update_database").handler().execute(
            context, Map.of("database_url", url, "description", "updated", "category", "firmware",
                "datecolumn", "Build Date", "functiontags", java.util.List.of("reviewed")), TaskMonitor.DUMMY);
        assertEquals("updated", updated.get("description"));
        assertEquals("Build Date", updated.get("date_column"));

        Map<String, Object> dropped = operation("drop_database").handler().execute(
            context, Map.of("database_url", url, "confirm", true), TaskMonitor.DUMMY);
        assertEquals(true, dropped.get("dropped"));
        assertFalse(java.nio.file.Files.exists(databaseFile.resolveSibling(
            databaseFile.getFileName() + ".mv.db")));
        }
    }

    @Test
    void createRefusesToAdoptExistingDatabaseWithMatchingName(@TempDir Path temporary) throws Exception {
        Path settings = temporary.resolve("settings");
        Path databaseFile = temporary.resolve("collision");
        BsimConnections connections = new BsimConnections(settings);
        try (BsimContext context = new BsimContext(null, null, connections, temporary, null)) {
        String url = databaseFile.toUri().toString();
        BsimOperation create = operation("create_database");
        boolean created = false;
        try {
            Map<String, Object> first = create.handler().execute(context,
                Map.of("database_url", url, "template", "medium_64.xml", "name", "Collision"),
                TaskMonitor.DUMMY);
            assertEquals("Collision", first.get("name"));
            created = true;

            IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> create.handler().execute(context,
                    Map.of("database_url", url, "template", "medium_64", "name", "Collision"),
                    TaskMonitor.DUMMY));
            assertTrue(failure.getMessage().contains("refusing to adopt"));
        }
        finally {
            if (created) {
                operation("drop_database").handler().execute(context,
                    Map.of("database_url", url, "confirm", true), TaskMonitor.DUMMY);
            }
        }
        }
    }

    private static BsimOperation operation(String name) {
        return BsimDatabaseOperations.operations().stream()
            .filter(operation -> operation.name().equals(name)).findFirst()
            .orElseThrow();
    }
}
