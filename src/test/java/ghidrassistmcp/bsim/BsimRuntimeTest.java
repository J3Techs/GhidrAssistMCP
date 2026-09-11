package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;

/** Async durable BSim jobs use only a disposable local H2 database. */
class BsimRuntimeTest {
    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.install.dir"))),
                new HeadlessGhidraApplicationConfiguration());
        }
    }

    @Test
    void asyncH2CreateSurvivesRuntimeRestart(@TempDir Path temporary) throws Exception {
        Path root = temporary.resolve("runtime");
        String url = temporary.resolve("async-fixture").toUri().toString();
        BsimOperation create = operation("create_database");
        BsimRuntime runtime = new BsimRuntime(root);
        String jobId;
        try {
            Map<String, Object> submitted = runtime.execute(create,
                Map.of("database_url", url, "template", "medium_64.xml", "name", "AsyncFixture"), null, null);
            jobId = (String) submitted.get("id");
            Map<String, Object> completed = awaitStatus(runtime, jobId, "COMPLETED");
            assertEquals("COMPLETED", completed.get("status"));

            Map<String, Object> info = runtime.execute(operation("database_info"),
                Map.of("database_url", url), null, null);
            assertEquals("AsyncFixture", info.get("name"));
        }
        finally {
            runtime.close();
        }

        BsimRuntime restarted = new BsimRuntime(root);
        try {
            Map<String, Object> persisted = restarted.control("get_results",
                Map.of("job_id", jobId, "offset", 0, "limit", 10), null);
            assertEquals("AsyncFixture", persisted.get("name"));

            Map<String, Object> dropped = restarted.execute(operation("drop_database"),
                Map.of("database_url", url, "confirm", true), null, null);
            awaitStatus(restarted, (String) dropped.get("id"), "COMPLETED");
        }
        finally {
            restarted.close();
        }
    }

    @Test
    void queuedUnknownOperationFinishesFailed(@TempDir Path temporary) throws Exception {
        BsimRuntime runtime = new BsimRuntime(temporary.resolve("runtime"));
        try {
            BsimOperation unknown = BsimOperation.of("unknown_operation", "test",
                Map.of("database_url", Map.of("type", "string")), List.of(), false, false, true,
                (context, arguments, monitor) -> Map.of("unexpected", true));
            Map<String, Object> submitted = runtime.execute(unknown,
                Map.of("database_url", "file:///does-not-matter"), null, null);
            Map<String, Object> failed = awaitTerminal(runtime, (String) submitted.get("id"));
            assertEquals("FAILED", failed.get("status"));
        }
        finally {
            runtime.close();
        }
    }

    private static Map<String, Object> awaitStatus(BsimRuntime runtime, String id, String wanted)
            throws Exception {
        Map<String, Object> result = awaitTerminal(runtime, id);
        assertEquals(wanted, result.get("status"), result::toString);
        return result;
    }

    private static Map<String, Object> awaitTerminal(BsimRuntime runtime, String id) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        Map<String, Object> result;
        do {
            result = runtime.control("get_job", Map.of("job_id", id), null);
            String status = String.valueOf(result.get("status"));
            if (Set.of("COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED").contains(status)) return result;
            Thread.sleep(25L);
        } while (System.nanoTime() < deadline);
        fail("Timed out waiting for BSim job: " + result);
        return result;
    }

    private static BsimOperation operation(String name) {
        return BsimRuntime.operations().stream().filter(operation -> operation.name().equals(name))
            .findFirst().orElseThrow();
    }
}
