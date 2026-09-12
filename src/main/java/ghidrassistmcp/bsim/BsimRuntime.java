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
    /** Drain only work owned by this backend; another GUI/headless backend stays usable. */
    public static void closeForBackend(GhidrAssistMCPBackend backend) {
        BsimRuntime runtime;
        synchronized (BsimRuntime.class) { runtime = instance; }
        if (runtime != null) runtime.drainBackend(backend, 20_000);
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
    private final Set<Work> outstanding = new HashSet<>();
    private final Set<GhidrAssistMCPBackend> stoppingOwners = Collections.newSetFromMap(new IdentityHashMap<>());
    private final Set<GhidrAssistMCPBackend> owners = Collections.newSetFromMap(new IdentityHashMap<>());
    private final Map<GhidrAssistMCPBackend, Integer> preparations = new IdentityHashMap<>();
    private volatile boolean terminated;
    private final class Work {
        final GhidrAssistMCPBackend owner;
        final BsimJobs.Job job;
        final Program program;
        final Object consumer = new Object();
        final TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
        FutureTask<?> future;
        boolean started;
        Work(GhidrAssistMCPBackend owner, BsimJobs.Job job, Program program) {
            this.owner = owner; this.job = job; this.program = program;
            if (program != null && !program.addConsumer(consumer))
                throw new IllegalStateException("BSim target program closed before admission");
        }
        void release() {
            if (program != null && !program.isClosed() && program.isUsedBy(consumer)) program.release(consumer);
        }
    }
    private final Map<String, BsimOperation> operations = new LinkedHashMap<>();
    public BsimRuntime(Path root) throws Exception {
        jobs = new BsimJobs(root.resolve("jobs")); connections = new BsimConnections(root);
        artifacts = root.resolve("artifacts"); Files.createDirectories(artifacts);
        for (BsimOperation op : operations()) {
            if (operations.put(op.name(), op) != null) throw new IllegalStateException("Duplicate BSim operation");
        }
    }
    public String lifecycleState() { return terminated ? "TERMINATED" : closed ? "STOPPING" : "RUNNING"; }

    private synchronized void checkOwner(GhidrAssistMCPBackend owner) {
        if (closed || stoppingOwners.contains(owner) || owner != null && owner.isStopping())
            throw new IllegalStateException("BSim runner/backend is stopping");
        owners.add(owner);
    }

    private <T> Future<T> submitOwned(GhidrAssistMCPBackend owner, BsimJobs.Job job, Program program,
            java.util.function.Function<TaskMonitorAdapter, T> action) {
        synchronized (this) {
            checkOwner(owner);
            Work work = new Work(owner, job, program);
            FutureTask<T> future = new FutureTask<>(() -> {
                synchronized (BsimRuntime.this) {
                    if (!outstanding.contains(work)) throw new CancellationException();
                    work.started = true;
                }
                try { return action.apply(work.monitor); }
                finally {
                    synchronized (BsimRuntime.this) { work.release(); outstanding.remove(work); BsimRuntime.this.notifyAll(); }
                }
            });
            work.future = future;
            outstanding.add(work);
            try { worker.execute(future); }
            catch (RuntimeException e) { work.release(); outstanding.remove(work); notifyAll(); throw e; }
            return future;
        }
    }

    private synchronized void cancelWork(Work work) {
        work.monitor.cancel();
        if (work.job != null) try { jobs.cancel(work.job.id()); }
            catch (Exception e) { ghidra.util.Msg.error(this, "Cannot persist BSim cancellation", e); }
        // Future completion does not prove a running callable stopped.
        work.future.cancel(true);
        if (!work.started) {
            work.release();
            outstanding.remove(work);
            if (work.job != null) { jobs.stopped(work.job); scheduled.remove(work.job.id()); }
            notifyAll();
        }
    }

    void drainBackend(GhidrAssistMCPBackend owner, long timeoutMillis) {
        boolean lastOwner;
        synchronized (this) {
            stoppingOwners.add(owner);
            for (Work work : List.copyOf(outstanding)) if (work.owner == owner) cancelWork(work);
            awaitOwned(owner, false, timeoutMillis);
            owners.remove(owner);
            lastOwner = owners.isEmpty();
            if (lastOwner) closed = true; // Close admission atomically with the final owner's departure.
        }
        if (lastOwner) close(timeoutMillis);
    }

    private void awaitOwned(GhidrAssistMCPBackend owner, boolean all, long timeoutMillis) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        while (outstanding.stream().anyMatch(work -> all || work.owner == owner)
                || (all ? !preparations.isEmpty() : preparations.containsKey(owner))) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) throw new IllegalStateException("BSim worker has not stopped; retain its project and program consumers");
            try { TimeUnit.NANOSECONDS.timedWait(this, remaining); }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while waiting for BSim worker shutdown; consumers retained", e);
            }
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
        synchronized (this) {
            checkOwner(backend);
            preparations.merge(backend, 1, Integer::sum);
        }
        try {
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
        return submitOwned(backend, null, program, monitor -> {
            try (BsimContext context = new BsimContext(program, backend, connections, artifacts, null)) {
                return BsimJobs.page(executeHandler(operation, context, args, monitor),
                    0, BsimSupport.integer(args, "result_limit", 100, 1000));
            } catch (Exception e) { throw new CompletionException(e); }
        }).get();
        } finally {
            synchronized (this) {
                preparations.computeIfPresent(backend, (owner, count) -> count == 1 ? null : count - 1);
                notifyAll();
            }
        }
    }
    private void queue(BsimJobs.Job job, Program program, GhidrAssistMCPBackend backend) throws Exception {
        if (!scheduled.add(job.id())) throw new IllegalStateException("Job already queued or running");
        job.transition("QUEUED", null);
        try { submitOwned(backend, job, program, monitor -> {
            try {
                if (job.status().equals("CANCELLED")) return null;
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
            return null;
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
        close(20_000);
    }

    void close(long timeoutMillis) {
        synchronized (this) {
            if (terminated) return;
            closed = true;
            for (Work work : List.copyOf(outstanding)) cancelWork(work);
            worker.shutdown();
            awaitOwned(null, true, timeoutMillis);
        }
        try {
            if (!worker.awaitTermination(timeoutMillis, TimeUnit.MILLISECONDS))
                throw new IllegalStateException("BSim worker has not stopped; consumers retained");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while stopping BSim; consumers retained", e);
        }
        synchronized (this) { terminated = true; }
        synchronized (BsimRuntime.class) { if (instance == this) instance = null; }
    }
}
