package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ghidra.util.task.TaskMonitorAdapter;

class BsimJobsTest {
    @Test void restartPreservesCheckpointsAndRequiresExplicitResume(@TempDir Path root) throws Exception {
        var jobs = new BsimJobs(root);
        var job = jobs.create("ingest", Map.of("database", "fixture"));
        jobs.start(job, new TaskMonitorAdapter(true));
        job.validateIdentity("source", Map.of("mtime", 12L, "version", 1));
        job.begin("a", Map.of("md5", "1234"));
        job.checkpoint("a", Map.of("inserted", true));
        job.begin("b", Map.of("md5", "5678"));
        var recovered = new BsimJobs(root).get(job.id());
        assertEquals("INTERRUPTED", recovered.status());
        assertEquals(true, recovered.completed("a").get("inserted"));
        assertEquals("5678", recovered.pending("b").get("md5"));
        assertDoesNotThrow(() -> recovered.validateIdentity("source", Map.of("mtime", 12L, "version", 1)));
        assertThrows(java.io.IOException.class, () -> recovered.validateIdentity("source", Map.of("mtime", 13L, "version", 1)));
    }
    @Test void resultsPageAndCancellationAndPurge(@TempDir Path root) throws Exception {
        var jobs = new BsimJobs(root);
        var job = jobs.create("query_program", Map.of());
        var monitor = new TaskMonitorAdapter(true);
        jobs.start(job, monitor); jobs.cancel(job.id()); assertTrue(monitor.isCancelled());
        assertThrows(IllegalStateException.class, () -> jobs.purge(job.id()));
        jobs.stopped(job);
        job.finish(Map.of("results", List.of(0, 1, 2, 3, 4)));
        assertEquals(List.of(2, 3), job.results("results", 2, 2).get("rows"));
        assertEquals(List.of(), job.results("results", 50, 2).get("rows"));
        assertEquals(true, job.results("results", 0, 2).get("truncated"));
        Path unrelated = root.resolve("keep.txt"); Files.writeString(unrelated, "keep");
        jobs.purge(job.id()); assertTrue(Files.exists(unrelated));
        assertThrows(IllegalArgumentException.class, () -> jobs.get(job.id()));
        assertThrows(IllegalArgumentException.class, () -> jobs.purge("../keep.txt"));
    }
    @Test void secretsCannotEnterJournal(@TempDir Path root) throws Exception {
        var jobs = new BsimJobs(root);
        assertThrows(IllegalArgumentException.class, () -> jobs.create("ingest", Map.of("database_url", "postgresql://user:secret@host/test")));
        assertThrows(IllegalArgumentException.class, () -> jobs.create("ingest", Map.of("nested", List.of(Map.of("password", "secret")))));
        assertEquals(0, jobs.count());
    }
    @Test void allPublicToolSchemasAreStructuredAndUnique() {
        var tools = BsimTool.tools();
        assertEquals(tools.size(), tools.stream().map(t -> t.getName()).distinct().count());
        for (var tool : tools) for (var entry : tool.getInputSchema().properties().entrySet()) {
            assertTrue(entry.getValue() instanceof Map, tool.getName() + ":" + entry.getKey());
            var schema = (Map<?, ?>) entry.getValue();
            assertTrue(Set.of("string", "array", "object", "integer", "number", "boolean").contains(schema.get("type")), tool.getName());
            if (schema.get("type").equals("array")) assertTrue(schema.containsKey("items"), tool.getName() + ":" + entry.getKey());
        }
    }
}
