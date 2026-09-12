/*
 * MCP Task state object for async task management.
 */
package ghidrassistmcp.tasks;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.LinkedHashMap;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import io.modelcontextprotocol.spec.McpSchema;

/**
 * Represents an asynchronous MCP task with its state and result.
 */
public class McpTask {

    /**
     * Task status enumeration
     */
    public enum Status {
        PENDING,    // Task is queued but not yet started
        RUNNING,    // Task is currently executing
        COMPLETED,  // Task completed successfully
        FAILED,     // Task failed with an error
        CANCEL_REQUESTED, // Cancellation was requested; worker has not settled
        CANCELLED   // Worker stopped before producing a normal result
    }

    private final String taskId;
    private final String toolName;
    private final Map<String, Object> arguments;
    private final McpProgramContext programContext;
    private final Instant createdAt;
    private volatile Status status;
    private volatile Instant startedAt;
    private volatile Instant completedAt;
    private volatile McpSchema.CallToolResult result;
    private volatile String resultRetentionCode;
    private volatile long retainedResultBytes;
    private volatile String errorMessage;
    private volatile int progressPercent;
    private volatile String progressMessage;
    private volatile long stateVersion;

    /**
     * Create a new task
     */
    public McpTask(String toolName, Map<String, Object> arguments) {
        this(toolName, arguments, McpProgramContext.empty());
    }

    /**
     * Create a new task with an immutable snapshot of its target program.
     */
    public McpTask(String toolName, Map<String, Object> arguments,
                   McpProgramContext programContext) {
        this.taskId = UUID.randomUUID().toString();
        this.toolName = toolName;
        this.arguments = freezeArguments(arguments);
        this.programContext = programContext != null
                ? programContext
                : McpProgramContext.empty();
        this.createdAt = Instant.now();
        this.status = Status.PENDING;
        this.progressPercent = 0;
        this.progressMessage = "Waiting to start...";
    }

    // Getters

    public String getTaskId() {
        return taskId;
    }

    /** Freeze JSON arguments, including nested containers, before a worker is queued. */
    public static Map<String, Object> freezeArguments(Map<String, Object> arguments) {
        Map<String, Object> copy = new LinkedHashMap<>();
        if (arguments != null) arguments.forEach((key, value) -> copy.put(key, freezeValue(value)));
        return Collections.unmodifiableMap(copy);
    }

    private static Object freezeValue(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> copy = new LinkedHashMap<>();
            map.forEach((key, nested) -> copy.put(key, freezeValue(nested)));
            return Collections.unmodifiableMap(copy);
        }
        if (value instanceof List<?> list) return Collections.unmodifiableList(
            list.stream().map(McpTask::freezeValue).collect(java.util.stream.Collectors.toList()));
        return value;
    }

    public long getStateVersion() { return stateVersion; }

    private void changed() { stateVersion++; notifyAll(); }

    /** Atomic, bounded metadata. Large operation results remain available via get_task_status. */
    public synchronized Map<String, Object> snapshot() {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("task_id", taskId);
        value.put("tool_name", clipped(toolName));
        value.put("state_version", stateVersion);
        value.put("status", status.name());
        value.put("terminal", isTerminal());
        value.put("progress_percent", progressPercent);
        value.put("progress_message", clipped(progressMessage));
        value.put("created_at", createdAt.toString());
        if (startedAt != null) value.put("started_at", startedAt.toString());
        if (completedAt != null) value.put("completed_at", completedAt.toString());
        value.put("duration_ms", getDurationMillis());
        value.put("result_available", isTerminal() && result != null);
        if (resultRetentionCode != null) value.put("result_retention_code", resultRetentionCode);
        value.put("retained_result_bytes", retainedResultBytes);
        if (errorMessage != null) value.put("error_message", clipped(errorMessage));
        Map<String, Object> program = new LinkedHashMap<>();
        if (programContext.programName() != null) program.put("name", clipped(programContext.programName()));
        if (programContext.projectPath() != null) program.put("project_path", clipped(programContext.projectPath()));
        if (programContext.fileId() != null) program.put("file_id", clipped(programContext.fileId()));
        if (programContext.programId() != null) program.put("program_id", clipped(programContext.programId()));
        value.put("program", program);
        value.put("metadata_truncated", List.of(
            Objects.toString(toolName, ""), Objects.toString(progressMessage, ""),
            Objects.toString(errorMessage, ""), Objects.toString(programContext.programName(), ""),
            Objects.toString(programContext.projectPath(), ""), Objects.toString(programContext.fileId(), ""),
            Objects.toString(programContext.programId(), "")).stream().anyMatch(s -> s.length() > 2048));
        return value;
    }

    private static String clipped(String value) {
        return value == null ? "" : value.substring(0, Math.min(value.length(), 2048));
    }

    /** Wait for completion, or a version change when a cursor is supplied. Never cancels the worker. */
    public synchronized Map<String, Object> awaitSnapshot(long timeoutMillis, Long afterVersion)
            throws InterruptedException {
        if (timeoutMillis < 0 || timeoutMillis > 30_000) throw new IllegalArgumentException("timeout_ms must be between 0 and 30000");
        if (afterVersion != null && (afterVersion < 0 || afterVersion > stateVersion))
            throw new IllegalArgumentException("after_version must be a previously observed state_version for this task");
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        while (!isTerminal() && (afterVersion == null || stateVersion <= afterVersion)) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) break;
            TimeUnit.NANOSECONDS.timedWait(this, remaining);
        }
        Map<String, Object> value = snapshot();
        boolean changed = afterVersion != null && stateVersion > afterVersion;
        value.put("wait_outcome", isTerminal() ? "terminal" : changed ? "changed" : "timeout");
        return value;
    }

    public String getToolName() {
        return toolName;
    }

    public Map<String, Object> getArguments() {
        return arguments;
    }

    public McpProgramContext getProgramContext() {
        return programContext;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public McpSchema.CallToolResult getResult() {
        return result;
    }

    public String getResultRetentionCode() { return resultRetentionCode; }
    public long getRetainedResultBytes() { return retainedResultBytes; }

    /** Drop only the retained payload; terminal operation status and error remain authoritative. */
    public synchronized void discardResult(String code) {
        if (result != null) result = null;
        retainedResultBytes = 0;
        resultRetentionCode = code;
        changed();
    }

    public synchronized void setRetainedResultBytes(long bytes) {
        retainedResultBytes = Math.max(0, bytes);
        resultRetentionCode = null;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public int getProgressPercent() {
        return progressPercent;
    }

    public String getProgressMessage() {
        return progressMessage;
    }

    // State transition methods

    /**
     * Mark task as started
     */
    public synchronized void markStarted() {
        if (this.status == Status.PENDING) {
            this.status = Status.RUNNING;
            this.startedAt = Instant.now();
            this.progressMessage = "Running...";
            changed();
        }
    }

    /**
     * Update task progress
     */
    public synchronized void updateProgress(int percent, String message) {
        if (this.status == Status.RUNNING) {
            if (this.progressPercent == Math.max(0, Math.min(100, percent)) && Objects.equals(this.progressMessage, message)) return;
            this.progressPercent = Math.max(0, Math.min(100, percent));
            this.progressMessage = message;
            changed();
        }
    }

    /**
     * Mark task as completed with result
     */
    public synchronized void markCompleted(McpSchema.CallToolResult taskResult) {
        if (this.status == Status.RUNNING || this.status == Status.PENDING || this.status == Status.CANCEL_REQUESTED) {
            // Publish the terminal state after its result fields.
            this.completedAt = Instant.now();
            this.result = resultRetentionCode == null ? taskResult : null;
            this.progressPercent = 100;
            this.progressMessage = "Completed";
            this.status = Status.COMPLETED;
            changed();
        }
    }

    /**
     * Mark task as failed with error
     */
    public synchronized void markFailed(String taskErrorMessage) {
        if (this.status == Status.RUNNING || this.status == Status.PENDING || this.status == Status.CANCEL_REQUESTED) {
            // Publish the terminal state after its result fields.
            this.completedAt = Instant.now();
            this.errorMessage = taskErrorMessage;
            this.progressMessage = "Failed: " + taskErrorMessage;
            this.status = Status.FAILED;
            changed();
        }
    }

    /**
     * Mark task as cancelled
     */
    public synchronized void markCancelled() {
        if (this.status == Status.PENDING || this.status == Status.RUNNING || this.status == Status.CANCEL_REQUESTED) {
            // Publish the terminal state after its result fields.
            this.completedAt = Instant.now();
            this.progressMessage = "Cancelled";
            this.status = Status.CANCELLED;
            changed();
        }
    }

    /** Admit the worker atomically against cancellation of queued tasks. */
    public synchronized boolean beginExecution() {
        if (status != Status.PENDING) return false;
        markStarted();
        return true;
    }

    /** Settle an operation that returned an MCP error while retaining its structured result. */
    public synchronized void markFailed(String taskErrorMessage, McpSchema.CallToolResult taskResult) {
        if (this.status == Status.RUNNING || this.status == Status.PENDING || this.status == Status.CANCEL_REQUESTED) {
            // Publish the terminal state after its result fields.
            this.completedAt = Instant.now();
            this.errorMessage = taskErrorMessage;
            this.result = resultRetentionCode == null ? taskResult : null;
            this.progressMessage = "Failed: " + taskErrorMessage;
            this.status = Status.FAILED;
            changed();
        }
    }

    /** Record a request without claiming that the worker has stopped. */
    public synchronized boolean requestCancellation() {
        if (this.status == Status.PENDING || this.status == Status.RUNNING) {
            this.status = Status.CANCEL_REQUESTED;
            this.progressMessage = "Cancellation requested; waiting for worker to stop...";
            changed();
            return true;
        }
        return false;
    }

    /**
     * Check if task is terminal (completed, failed, or cancelled)
     */
    public boolean isTerminal() {
        Status s = this.status;
        return s == Status.COMPLETED || s == Status.FAILED || s == Status.CANCELLED;
    }

    /**
     * Get duration in milliseconds (or elapsed time if still running)
     */
    public long getDurationMillis() {
        if (startedAt == null) {
            return 0;
        }
        Instant end = completedAt != null ? completedAt : Instant.now();
        return end.toEpochMilli() - startedAt.toEpochMilli();
    }

    /**
     * Generate a summary string for display
     */
    public String toSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Task ID: ").append(taskId).append("\n");
        sb.append("Tool: ").append(toolName).append("\n");
        sb.append("Status: ").append(status).append("\n");
        sb.append("Progress: ").append(progressPercent).append("% - ").append(progressMessage).append("\n");
        sb.append("Created: ").append(createdAt).append("\n");

        if (startedAt != null) {
            sb.append("Started: ").append(startedAt).append("\n");
        }

        if (completedAt != null) {
            sb.append("Completed: ").append(completedAt).append("\n");
            sb.append("Duration: ").append(getDurationMillis()).append("ms\n");
        }

        if (errorMessage != null) {
            sb.append("Error: ").append(errorMessage).append("\n");
        }

        return sb.toString();
    }
}
