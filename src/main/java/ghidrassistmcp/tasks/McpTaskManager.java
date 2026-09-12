/*
 * MCP Task Manager for async task execution and tracking.
 */
package ghidrassistmcp.tasks;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import com.fasterxml.jackson.databind.ObjectMapper;

import ghidra.util.Msg;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Manages asynchronous MCP task execution and tracking.
 * Provides task submission, status tracking, and cancellation capabilities.
 */
public class McpTaskManager {

    private static final int DEFAULT_THREAD_POOL_SIZE = 4;
    private static final int TASK_RETENTION_HOURS = 1;
    private static final int DEFAULT_QUEUE_CAPACITY = 64;
    private static final long DEFAULT_MAX_TOTAL_RESULT_BYTES = 64L * 1024 * 1024;
    private static final long DEFAULT_MAX_RESULT_BYTES = 4L * 1024 * 1024;
    private static final int DEFAULT_MAX_TERMINAL_TASKS = 1024;

    private final Map<String, McpTask> tasks = new ConcurrentHashMap<>();
    private final Map<String, Future<?>> taskFutures = new ConcurrentHashMap<>();
    private final Map<String, Runnable> taskCleanup = new ConcurrentHashMap<>();
    private final ThreadPoolExecutor executor;
    private final long maxTotalResultBytes, maxResultBytes, retentionMillis;
    private final int maxTerminalTasks;
    private final java.util.concurrent.atomic.AtomicLong retainedResultBytes = new java.util.concurrent.atomic.AtomicLong();
    private final Object retentionLock = new Object();
    private static final ObjectMapper JSON = new ObjectMapper();
    private final String instanceId = java.util.UUID.randomUUID().toString();

    public String getInstanceId() { return instanceId; }

    /** Custom tool lifecycle, scoped to this manager process; not negotiated MCP Tasks. */
    public Map<String, Object> waitForTask(String taskId, long timeoutMillis, Long afterVersion)
            throws InterruptedException {
        McpTask task = getTask(taskId);
        if (task == null) throw new IllegalArgumentException("Task not found: " + taskId);
        Map<String, Object> snapshot = task.awaitSnapshot(timeoutMillis, afterVersion);
        addLifecycleMetadata(snapshot);
        return snapshot;
    }

    public Map<String, Object> waitForTaskSnapshot(McpTask task) {
        Map<String, Object> snapshot = task.snapshot();
        addLifecycleMetadata(snapshot);
        return snapshot;
    }

    private void addLifecycleMetadata(Map<String, Object> snapshot) {
        snapshot.put("schema_version", 1);
        snapshot.put("manager_instance_id", instanceId);
        snapshot.put("lifecycle", "custom_in_memory");
        snapshot.put("result_tool", "get_task_status");
    }

    /**
     * Create a new task manager with default thread pool size
     */
    public McpTaskManager() {
        this(DEFAULT_THREAD_POOL_SIZE, DEFAULT_QUEUE_CAPACITY);
    }

    /**
     * Create a new task manager with specified thread pool size
     */
    public McpTaskManager(int threadPoolSize) {
        this(threadPoolSize, DEFAULT_QUEUE_CAPACITY);
    }

    public McpTaskManager(int threadPoolSize, int queueCapacity) {
        this(threadPoolSize, queueCapacity, DEFAULT_MAX_TOTAL_RESULT_BYTES, DEFAULT_MAX_RESULT_BYTES,
            DEFAULT_MAX_TERMINAL_TASKS, TimeUnit.HOURS.toMillis(TASK_RETENTION_HOURS));
    }

    /** Injectable limits make admission and retention behavior deterministic in fixture tests. */
    public McpTaskManager(int threadPoolSize, int queueCapacity, long maxTotalResultBytes,
            long maxResultBytes, int maxTerminalTasks, long retentionMillis) {
        if (threadPoolSize < 1 || queueCapacity < 1 || maxTotalResultBytes < 0 || maxResultBytes < 0
                || maxTerminalTasks < 1 || retentionMillis < 0)
            throw new IllegalArgumentException("invalid task manager limits");
        this.maxTotalResultBytes = maxTotalResultBytes; this.maxResultBytes = maxResultBytes;
        this.maxTerminalTasks = maxTerminalTasks; this.retentionMillis = retentionMillis;
        this.executor = new ThreadPoolExecutor(threadPoolSize, threadPoolSize, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(queueCapacity), r -> {
            Thread t = new Thread(r);
            t.setName("MCP-Task-" + t.threadId());
            t.setDaemon(true);
            return t;
        }, new ThreadPoolExecutor.AbortPolicy());
        Msg.info(this, "McpTaskManager initialized with " + threadPoolSize + " threads");
    }

    /**
     * Submit a new async task for execution
     *
     * @param toolName The name of the tool being executed
     * @param arguments The tool arguments
     * @param taskExecutor A supplier that executes the tool and returns the result
     * @return The created task
     */
    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               Supplier<McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, task -> taskExecutor.get());
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               McpProgramContext programContext,
                               Supplier<McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, programContext, task -> taskExecutor.get());
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, McpProgramContext.empty(), taskExecutor);
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               McpProgramContext programContext,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        return submitTask(toolName, arguments, programContext, taskExecutor, () -> {});
    }

    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                               McpProgramContext programContext,
                               Function<McpTask, McpSchema.CallToolResult> taskExecutor, Runnable cleanup) {
        // Clean up old tasks before creating new ones
        cleanupOldTasks();

        McpTask task = new McpTask(toolName, arguments, programContext);
        taskCleanup.put(task.getTaskId(), cleanup);

        FutureTask<Void> future = new FutureTask<>(() -> {
            try {
                if (!task.beginExecution()) { task.markCancelled(); return; }
                Msg.info(this, "Task started: " + task.getTaskId() + " for tool: " + toolName);

                McpSchema.CallToolResult result = taskExecutor.apply(task);
                if (result == null) {
                    task.markFailed("Operation returned no result");
                } else if (Boolean.TRUE.equals(result.isError())) {
                    retainResult(task, result);
                    task.markFailed("Operation returned an MCP error", result);
                } else {
                    retainResult(task, result);
                    task.markCompleted(result);
                }
                cleanupOldTasks();

                Msg.info(this, "Task completed: " + task.getTaskId() + " in " + task.getDurationMillis() + "ms");

            } catch (CancellationException e) {
                task.markCancelled();
                Msg.info(this, "Task cancelled before execution: " + task.getTaskId());
            } catch (Exception e) {
                if (task.getStatus() == McpTask.Status.CANCEL_REQUESTED || Thread.currentThread().isInterrupted()) {
                    task.markCancelled();
                    Msg.info(this, "Task cancelled after worker stopped: " + task.getTaskId());
                } else {
                    task.markFailed(e.getMessage());
                    Msg.error(this, "Task failed: " + task.getTaskId() + " - " + e.getMessage(), e);
                }
            } finally { cleanupOldTasks(); taskFutures.remove(task.getTaskId()); releaseTask(task.getTaskId()); }
        }, null);
        // Publish the cancellation handle before admitting execution; a fast worker or
        // concurrent cancellation must never observe a task without its Future.
        taskFutures.put(task.getTaskId(), future);
        tasks.put(task.getTaskId(), task);
        try { executor.execute(future); }
        catch (RuntimeException e) {
            tasks.remove(task.getTaskId()); taskFutures.remove(task.getTaskId());
            releaseTask(task.getTaskId()); throw e;
        }
        Msg.info(this, "Task submitted: " + task.getTaskId() + " for tool: " + toolName);

        return task;
    }

    private void releaseTask(String id) { Runnable cleanup = taskCleanup.remove(id); if (cleanup != null) cleanup.run(); }

    /**
     * Get a task by ID
     */
    public McpTask getTask(String taskId) {
        cleanupOldTasks();
        return tasks.get(taskId);
    }

    /**
     * Get task status summary
     */
    public String getTaskStatus(String taskId) {
        cleanupOldTasks();
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return "Task not found: " + taskId;
        }
        return task.toSummary();
    }

    /**
     * Get the result of a completed task
     */
    public McpSchema.CallToolResult getTaskResult(String taskId) {
        McpTask task = getTask(taskId);
        if (task == null) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Task not found: " + taskId)
                .build();
        }

        if (!task.isTerminal()) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("Task is still running.\n" + task.toSummary())
                .build();
        }

        McpSchema.CallToolResult retained = task.getResult();
        if (retained != null) return retained;
        String retentionCode = task.getResultRetentionCode();
        if (retentionCode != null) {
            return McpSchema.CallToolResult.builder().isError(true)
                .structuredContent(Map.of("code", retentionCode, "task_id", taskId,
                    "operation_status", task.getStatus().name(), "result_available", false))
                .addTextContent(retentionCode + ": terminal payload is unavailable; operation status is " + task.getStatus())
                .build();
        }

        if (task.getStatus() == McpTask.Status.FAILED) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Task failed: " + task.getErrorMessage())
                .build();
        }

        if (task.getStatus() == McpTask.Status.COMPLETED && task.getResultRetentionCode() != null) {
            return McpSchema.CallToolResult.builder().isError(true)
                .addTextContent(task.getResultRetentionCode() + ": terminal task result was evicted; operation status is COMPLETED")
                .build();
        }

        if (task.getStatus() == McpTask.Status.CANCELLED) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Task was cancelled")
                .build();
        }

        return McpSchema.CallToolResult.builder()
            .addTextContent("Unknown task state: " + task.getStatus())
            .build();
    }

    /**
     * Cancel a running task
     */
    public boolean cancelTask(String taskId) {
        McpTask task = tasks.get(taskId);
        if (task == null) {
            return false;
        }

        if (task.isTerminal()) {
            return false; // Can't cancel a completed task
        }

        Future<?> future = taskFutures.get(taskId);
        boolean requested = task.requestCancellation();
        if (!requested) return false;
        if (future != null) {
            boolean stoppedBeforeStart = future.cancel(true);
            // Remove a queued Future so rejection capacity is returned immediately.
            if (stoppedBeforeStart && task.getStartedAt() == null) {
                executor.remove((Runnable) future); task.markCancelled(); taskFutures.remove(taskId); releaseTask(taskId);
            }
        }
        Msg.info(this, "Cancellation requested: " + taskId);
        return true;
    }

    /**
     * List all tasks with optional status filter
     */
    public List<McpTask> listTasks(McpTask.Status statusFilter) {
        cleanupOldTasks();
        if (statusFilter == null) {
            return new ArrayList<>(tasks.values());
        }

        return tasks.values().stream()
            .filter(t -> t.getStatus() == statusFilter)
            .collect(Collectors.toList());
    }

    /**
     * Get a summary of all active tasks
     */
    public String getTasksSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("MCP Tasks Summary:\n\n");

        long pending = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.PENDING).count();
        long running = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.RUNNING).count();
        long completed = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.COMPLETED).count();
        long failed = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.FAILED).count();
        long cancelled = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.CANCELLED).count();
        long cancelling = tasks.values().stream().filter(t -> t.getStatus() == McpTask.Status.CANCEL_REQUESTED).count();

        sb.append("Total: ").append(tasks.size()).append("\n");
        sb.append("  Pending: ").append(pending).append("\n");
        sb.append("  Running: ").append(running).append("\n");
        sb.append("  Cancellation requested: ").append(cancelling).append("\n");
        sb.append("  Completed: ").append(completed).append("\n");
        sb.append("  Failed: ").append(failed).append("\n");
        sb.append("  Cancelled: ").append(cancelled).append("\n\n");

        if (!tasks.isEmpty()) {
            sb.append("Tasks:\n");
            tasks.values().stream()
                .sorted((a, b) -> b.getCreatedAt().compareTo(a.getCreatedAt())) // Most recent first
                .limit(20) // Limit to 20 most recent
                .forEach(task -> {
                    sb.append("  - ").append(task.getTaskId())
                      .append(" | ").append(task.getToolName())
                      .append(" | ").append(task.getStatus())
                      .append(" | ").append(task.getProgressPercent()).append("%")
                      .append("\n");
                });
        }

        return sb.toString();
    }

    /**
     * Clean up old completed tasks
     */
    private void cleanupOldTasks() {
        synchronized (retentionLock) {
        Instant cutoff = Instant.now().minusMillis(retentionMillis);

        List<String> toRemove = tasks.entrySet().stream()
            .filter(e -> e.getValue().isTerminal())
            .filter(e -> e.getValue().getCompletedAt() != null && e.getValue().getCompletedAt().isBefore(cutoff))
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());

        for (String taskId : toRemove) {
            McpTask removed = tasks.remove(taskId);
            if (removed != null) evictPayload(removed);
            taskFutures.remove(taskId);
        }

        List<McpTask> terminal = tasks.values().stream().filter(McpTask::isTerminal)
            .sorted(java.util.Comparator.comparing(McpTask::getCompletedAt, java.util.Comparator.nullsLast(java.util.Comparator.naturalOrder())))
            .collect(Collectors.toList());
        for (int i = 0; i < Math.max(0, terminal.size() - maxTerminalTasks); i++) {
            McpTask old = terminal.get(i);
            evictPayload(old);
            tasks.remove(old.getTaskId(), old);
            taskFutures.remove(old.getTaskId());
        }

        if (!toRemove.isEmpty()) {
            Msg.info(this, "Cleaned up " + toRemove.size() + " old tasks");
        }
        }
    }

    private void retainResult(McpTask task, McpSchema.CallToolResult result) {
        synchronized (retentionLock) {
        if (result == null) return;
        final long bytes;
        try {
            bytes = JSON.writeValueAsBytes(result).length;
        }
        catch (Exception e) { task.discardResult("RESULT_TOO_LARGE"); return; }
        if (bytes > maxResultBytes) { task.discardResult("RESULT_TOO_LARGE"); return; }
        while (retainedResultBytes.get() + bytes > maxTotalResultBytes) {
            McpTask victim = tasks.values().stream().filter(t -> t != task && t.isTerminal() && t.getResult() != null)
                .min(java.util.Comparator.comparing(McpTask::getCompletedAt, java.util.Comparator.nullsLast(java.util.Comparator.naturalOrder()))).orElse(null);
            if (victim == null) { task.discardResult("RESULT_EXPIRED"); return; }
            evictPayload(victim);
        }
        task.setRetainedResultBytes(bytes); retainedResultBytes.addAndGet(bytes);
        }
    }

    private void evictPayload(McpTask task) {
        long bytes = task.getRetainedResultBytes();
        if (bytes == 0 && task.getResult() == null) return;
        task.discardResult("RESULT_EXPIRED"); retainedResultBytes.addAndGet(-bytes);
    }

    /**
     * Shutdown the task manager
     */
    public void shutdown() {
        Msg.info(this, "Shutting down McpTaskManager...");
        executor.shutdown();
        for (McpTask task : tasks.values()) if (!task.isTerminal()) cancelTask(task.getTaskId());
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                for (McpTask task : tasks.values()) if (!task.isTerminal()) cancelTask(task.getTaskId());
                executor.shutdownNow();
                if (!executor.awaitTermination(10, TimeUnit.SECONDS))
                    throw new IllegalStateException("MCP workers have not stopped; program consumers are retained");
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while stopping MCP workers; program consumers are retained", e);
        }
        Msg.info(this, "McpTaskManager shut down");
    }
}
