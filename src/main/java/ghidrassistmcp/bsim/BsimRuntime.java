package ghidrassistmcp.bsim;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidrassistmcp.GhidrAssistMCPBackend;

/** Lazily initialized durable BSim runner. A single worker serializes local H2 clients. */
public final class BsimRuntime implements AutoCloseable {
    private static BsimRuntime instance;
    public static void closeIfInitialized() {
        BsimRuntime runtime;
        synchronized (BsimRuntime.class) { runtime = instance; }
        if (runtime != null) runtime.close();
    }
    public static synchronized BsimRuntime instance() throws Exception {
        if (instance == null) instance = new BsimRuntime(Application.getUserSettingsDirectory().toPath().resolve("ghidrassistmcp-bsim"));
        return instance;
    }
    private final BsimJobs jobs;
    private final BsimConnections connections;
    private final Path artifacts;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "GhidrAssistMCP-BSim"); thread.setDaemon(true); return thread;
    });
    private final Set<String> scheduled = ConcurrentHashMap.newKeySet();
    private volatile boolean closed;
    private final Map<String, BsimOperation> operations = new LinkedHashMap<>();
    public BsimRuntime(Path root) throws Exception {
        jobs = new BsimJobs(root.resolve("jobs")); connections = new BsimConnections(root);
        artifacts = root.resolve("artifacts"); Files.createDirectories(artifacts);
        for (BsimOperation op : operations()) {
            if (operations.put(op.name(), op) != null) throw new IllegalStateException("Duplicate BSim operation");
        }
    }
    public static List<BsimOperation> operations() {
        List<BsimOperation> result = new ArrayList<>();
        result.addAll(BsimDatabaseOperations.operations()); result.addAll(BsimCorpusOperations.operations());
        result.addAll(BsimQueryOperations.operations()); result.addAll(BsimMatchOperations.operations());
        return List.copyOf(result);
    }
    private Map<String,Object> executeHandler(BsimOperation operation,BsimContext context,
            Map<String,Object> arguments,ghidra.util.task.TaskMonitor monitor)throws Exception{
        boolean write=!operation.readOnly();
        if(write)ghidrassistmcp.McpMutationGuard.LOCK.lockInterruptibly();
        try{monitor.checkCancelled();return operation.handler().execute(context,arguments,monitor);}
        finally{if(write)ghidrassistmcp.McpMutationGuard.LOCK.unlock();}
    }
    public Map<String, Object> execute(BsimOperation operation, Map<String, Object> arguments,
            Program program, GhidrAssistMCPBackend backend) throws Exception {
        BsimJobs.rejectSecrets(arguments);
        if (closed) throw new IllegalStateException("BSim runner is closed");
        Map<String, Object> args = new LinkedHashMap<>(arguments);
        if (operation.longRunning()) {
            BsimJobs.Job job = jobs.create(operation.name(), args);
            boolean sourcePrograms = Set.of("generate_signatures", "query_program", "query_functions", "overview", "match_programs").contains(operation.name())
                || Set.of("ingest", "update_metadata").contains(operation.name()) && !args.containsKey("xml_directory")
                || operation.name().equals("query_vectors") && !args.containsKey("vector_ids")
                || operation.name().equals("rebuild_corpus") && (args.containsKey("programs") || args.containsKey("project_folder"));
            if (sourcePrograms) {
                try (BsimContext context = new BsimContext(program, backend, connections, artifacts, job)) {
                    job.setArguments(context.snapshotPrograms(args, new TaskMonitorAdapter(true)));
                } catch (Exception e) { job.transition("FAILED", e.getMessage()); throw e; }
            }
            queue(job, program, backend);
            return job.summary();
        }
        // All client work shares the same worker, including synchronous operations.
        return worker.submit(() -> {
            try (BsimContext context = new BsimContext(program, backend, connections, artifacts, null)) {
                return BsimJobs.page(executeHandler(operation, context, args, new TaskMonitorAdapter(true)),
                    0, BsimSupport.integer(args, "result_limit", 100, 1000));
            }
        }).get();
    }
    private void queue(BsimJobs.Job job, Program program, GhidrAssistMCPBackend backend) throws Exception {
        if (!scheduled.add(job.id())) throw new IllegalStateException("Job already queued or running");
        job.transition("QUEUED", null);
        try { worker.submit(() -> {
            TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
            try {
                if (job.status().equals("CANCELLED")) return;
                jobs.start(job, monitor);
                BsimOperation operation = operations.get(job.operation());
                if (operation == null) throw new IllegalArgumentException("Operation is no longer available");
                try (BsimContext context = new BsimContext(program, backend, connections, artifacts, job)) {
                    if (job.arguments().containsKey("programs")) context.validateProgramFiles(job.arguments(), monitor);
                    var result = executeHandler(operation, context, job.arguments(), monitor);
                    monitor.checkCancelled(); job.finish(result);
                }
            } catch (Exception e) {
                try { job.transition(e instanceof CancelledException || monitor.isCancelled() ? "CANCELLED" : "FAILED", e.getMessage()); }
                catch (Exception journalFailure) { ghidra.util.Msg.error(this, "Cannot persist BSim job failure", journalFailure); }
            } finally { jobs.stopped(job); scheduled.remove(job.id()); }
        }); } catch (RuntimeException e) { scheduled.remove(job.id()); job.transition("INTERRUPTED", "Job submission failed; explicitly resume"); throw e; }
    }
    public Map<String, Object> control(String operation, Map<String, Object> args, GhidrAssistMCPBackend backend) throws Exception {
        int offset = BsimSupport.integer(args, "offset", 0, Integer.MAX_VALUE);
        int limit = BsimSupport.integer(args, "limit", 100, 1000);
        if (operation.equals("list_jobs")) return Map.of("jobs", jobs.list(offset, limit), "total", jobs.count(), "offset", offset);
        BsimJobs.Job job = jobs.get(BsimSupport.text(args, "job_id"));
        return switch (operation) {
            case "get_job" -> job.summary();
            case "get_results" -> job.results(BsimSupport.text(args, "field", null), offset, limit);
            case "cancel_job" -> { jobs.cancel(job.id()); yield job.summary(); }
            case "resume_job" -> {
                if (Set.of("COMPLETED", "RUNNING", "QUEUED").contains(job.status())) throw new IllegalStateException("Cannot resume a " + job.status() + " job");
                queue(job, null, backend); yield job.summary();
            }
            case "purge_job" -> {
                if (!BsimSupport.bool(args, "confirm", false)) throw new IllegalArgumentException("confirm=true is required");
                if (scheduled.contains(job.id())) throw new IllegalStateException("Wait for the job to stop before purging");
                jobs.purge(job.id()); yield Map.of("job_id", job.id(), "purged", true, "corpus_artifacts_retained", true);
            }
            default -> throw new IllegalArgumentException("Unknown job operation");
        };
    }
    @Override public void close() {
        closed = true;
        for (String id : scheduled) try { jobs.cancel(id); } catch (Exception e) { ghidra.util.Msg.error(this, "Cannot cancel BSim job", e); }
        worker.shutdownNow();
        try {
            if (!worker.awaitTermination(20, TimeUnit.SECONDS))
                throw new IllegalStateException("BSim worker has not stopped; retain its project and program consumers");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for BSim worker shutdown", e);
        }
        for (String id : scheduled) try { jobs.get(id).transition("INTERRUPTED", "BSim runner closed; explicitly resume"); } catch (Exception e) { ghidra.util.Msg.error(this, "Cannot persist interrupted BSim job", e); }
        synchronized (BsimRuntime.class) { if (instance == this) instance = null; }
    }
}
