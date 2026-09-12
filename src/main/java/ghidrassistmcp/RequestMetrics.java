package ghidrassistmcp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Bounded, privacy-preserving per-request timing samples. */
public final class RequestMetrics {
    public static final int MAX_RECORDS = 256;
    private static final ObjectMapper JSON = new ObjectMapper();
    private final ArrayDeque<Record> ring = new ArrayDeque<>(MAX_RECORDS);

    public Sample start(String toolName) {
        return new Sample(this, UUID.randomUUID().toString(), canonicalTool(toolName), "submission");
    }

    public synchronized List<Record> snapshot() {
        return List.copyOf(ring);
    }

    private synchronized void add(Record record) {
        if (ring.size() >= MAX_RECORDS) ring.removeFirst();
        ring.addLast(record);
    }

    private static String canonicalTool(String value) {
        if (value == null || value.isBlank()) return "unknown";
        String text = value.trim();
        int separator = text.indexOf(':');
        if (separator > 0) text = text.substring(0, separator);
        return text.length() > 128 ? text.substring(0, 128) : text;
    }

    public static final class Record {
        private final String correlationId, toolName, kind;
        private final Map<String, Long> durationsMillis;
        private final long encodedResultBytes;
        private final boolean complete;

        private Record(String correlationId, String toolName, String kind, Map<String, Long> durationsMillis,
                long encodedResultBytes, boolean complete) {
            this.correlationId = correlationId; this.toolName = toolName; this.kind = kind;
            this.durationsMillis = Map.copyOf(durationsMillis); this.encodedResultBytes = encodedResultBytes;
            this.complete = complete;
        }
        public String correlationId() { return correlationId; }
        public String toolName() { return toolName; }
        public String kind() { return kind; }
        public Map<String, Long> durationsMillis() { return durationsMillis; }
        public long encodedResultBytes() { return encodedResultBytes; }
        public boolean complete() { return complete; }
    }

    public static final class Sample {
        private final RequestMetrics owner;
        private final String correlationId, toolName, kind;
        private final long started;
        private final Map<String, Long> phaseStarted = new LinkedHashMap<>();
        private final Map<String, Long> durations = new LinkedHashMap<>();
        private boolean finished;

        private Sample(RequestMetrics owner, String correlationId, String toolName, String kind) {
            this.owner = owner; this.correlationId = correlationId; this.toolName = toolName; this.kind = kind;
            this.started = System.nanoTime();
        }

        /** Create a distinct worker-completion record sharing this request correlation ID. */
        public Sample forkWorker() {
            return new Sample(owner, correlationId, toolName, "worker_completion");
        }

        public synchronized Sample begin(String phase) {
            if (!finished && validPhase(phase)) phaseStarted.put(phase, System.nanoTime());
            return this;
        }

        public synchronized Sample end(String phase) {
            if (!finished && validPhase(phase)) {
                Long start = phaseStarted.remove(phase);
                if (start != null) durations.put(phase, elapsedMillis(start));
            }
            return this;
        }

        /** Finish is best-effort; serialization/timing failures never escape to the operation. */
        public synchronized void finish(Object result) {
            if (finished) return;
            for (String phase : new ArrayList<>(phaseStarted.keySet())) end(phase);
            finished = true;
            long serializationStart = System.nanoTime();
            long bytes = encodedBytes(result);
            Map<String, Long> completed = new LinkedHashMap<>(durations);
            completed.put("serialization", elapsedMillis(serializationStart));
            completed.putIfAbsent("total", elapsedMillis(started));
            owner.add(new Record(correlationId, toolName, kind, completed, bytes, true));
        }

        private long elapsedMillis(long start) { return TimeUnit.NANOSECONDS.toMillis(Math.max(0, System.nanoTime() - start)); }
        private static boolean validPhase(String phase) {
            return phase != null && switch (phase) {
                case "selection", "queue", "writer_guard", "execution", "serialization" -> true;
                default -> false;
            };
        }
    }

    private static long encodedBytes(Object result) {
        if (result == null) return 0;
        try (CountingOutputStream out = new CountingOutputStream()) {
            JSON.writeValue(out, result);
            return out.count;
        } catch (Exception ignored) { return -1; }
    }

    private static final class CountingOutputStream extends OutputStream {
        long count;
        @Override public void write(int value) { count++; }
        @Override public void write(byte[] bytes, int off, int len) throws IOException {
            if (len > 0) count += len;
        }
    }
}
