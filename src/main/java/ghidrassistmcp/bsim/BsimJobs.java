package ghidrassistmcp.bsim;

import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import ghidra.util.task.TaskMonitor;

/** Durable BSim work journal. Construction recovers interrupted jobs without executing them. */
public final class BsimJobs {
    private final Path root;
    private final Map<String, Job> jobs = new ConcurrentHashMap<>();
    private final Map<String, TaskMonitor> active = new ConcurrentHashMap<>();
    public BsimJobs(Path root) throws IOException {
        this.root = root.toAbsolutePath().normalize();
        Files.createDirectories(this.root);
        try (var directories = Files.list(this.root)) {
            for (Path directory : directories.filter(Files::isDirectory).toList()) {
                Path manifest = directory.resolve("manifest.json");
                if (!Files.isRegularFile(manifest)) continue;
                Map<String, Object> data = BsimSupport.readJson(manifest);
                if (!Objects.equals(data.get("schema_version"), 1)) continue;
                String id = String.valueOf(data.get("id"));
                if (!validId(id) || !directory.getFileName().toString().equals(id)) continue;
                Job job = new Job(directory, data);
                if (Set.of("RUNNING", "QUEUED").contains(job.status())) job.transition("INTERRUPTED", "Ghidra stopped; explicitly resume this job");
                jobs.put(id, job);
            }
        }
    }
    public Job create(String operation, Map<String, Object> arguments) throws IOException {
        rejectSecrets(arguments);
        String id = UUID.randomUUID().toString();
        var data = new LinkedHashMap<String, Object>();
        data.put("schema_version", 1); data.put("id", id); data.put("operation", operation);
        data.put("arguments", BsimSupport.copy(arguments)); data.put("created_at", Instant.now().toString());
        data.put("status", "QUEUED"); data.put("identities", new LinkedHashMap<>());
        data.put("checkpoints", new LinkedHashMap<>()); data.put("pending", new LinkedHashMap<>());
        Job job = new Job(root.resolve(id), data); job.save(); jobs.put(id, job); return job;
    }
    public Job get(String id) {
        if (!validId(id) || !jobs.containsKey(id)) throw new IllegalArgumentException("Unknown BSim job: " + id);
        return jobs.get(id);
    }
    public List<Map<String, Object>> list(int offset, int limit) {
        return jobs.values().stream().sorted(Comparator.comparing((Job j) -> String.valueOf(j.data.get("created_at"))).reversed())
            .skip(offset).limit(limit).map(Job::summary).toList();
    }
    public int count() { return jobs.size(); }
    public void start(Job job, TaskMonitor monitor) throws IOException {
        if (active.putIfAbsent(job.id(), monitor) != null) throw new IllegalStateException("Job is already running");
        try { job.transition("RUNNING", null); } catch (IOException e) { active.remove(job.id()); throw e; }
    }
    public void stopped(Job job) { active.remove(job.id()); }
    public void cancel(String id) throws IOException {
        Job job = get(id);
        TaskMonitor monitor = active.get(id);
        if (monitor != null) { monitor.cancel(); job.note("Cancellation requested; any active database commit must settle before resuming"); }
        else if (!Set.of("COMPLETED", "PURGED").contains(job.status())) job.transition("CANCELLED", "Cancelled while inactive");
    }
    public void purge(String id) throws IOException {
        Job job = get(id);
        if (active.containsKey(id)) throw new IllegalStateException("Cancel and wait for the job before purging");
        Path directory = job.directory.toRealPath();
        if (!directory.getParent().equals(root.toRealPath()) || !directory.getFileName().toString().equals(id)) throw new IOException("Invalid job artifact path");
        // Journal files are fixed names. Corpus/export files live elsewhere and are never removed here.
        Files.deleteIfExists(directory.resolve("result.json"));
        try (var files = Files.list(directory)) {
            for (Path file : files.filter(Files::isRegularFile).toList()) {
                if (file.getFileName().toString().matches("(?:rows-[0-9a-f]+\\.jsonl|unit-[0-9a-f]+\\.json)")) Files.delete(file);
            }
        }
        Files.deleteIfExists(directory.resolve("manifest.json"));
        Files.delete(directory);
        jobs.remove(id);
    }
    private static boolean validId(String id) {
        try { return UUID.fromString(id).toString().equals(id); } catch (RuntimeException e) { return false; }
    }
    static void rejectSecrets(Object value) {
        if (value instanceof Map<?, ?> map) {
            for (var entry : map.entrySet()) {
                String key = entry.getKey().toString().toLowerCase(Locale.ROOT);
                if (key.matches(".*(?:password|passwd|token|secret|private_key|api_key|credential).*"))
                    throw new IllegalArgumentException("Use Ghidra authentication; secrets cannot be stored in BSim job arguments");
                rejectSecrets(entry.getValue());
            }
        } else if (value instanceof List<?> list) { for (Object item : list) rejectSecrets(item); }
        else if (value instanceof String string && !BsimSupport.redact(string).equals(string))
            throw new IllegalArgumentException("Passwords in database URLs are not accepted");
    }
    public static final class Job {
        private final Path directory;
        private final Map<String, Object> data;
        private Job(Path directory, Map<String, Object> data) { this.directory = directory; this.data = data; }
        public synchronized String id() { return (String) data.get("id"); }
        public synchronized String operation() { return (String) data.get("operation"); }
        public synchronized String status() { return (String) data.get("status"); }
        @SuppressWarnings("unchecked") public synchronized Map<String, Object> arguments() { return BsimSupport.copy((Map<String, Object>) data.get("arguments")); }
        public synchronized void setArguments(Map<String, Object> arguments) throws IOException {
            rejectSecrets(arguments); data.put("arguments", BsimSupport.copy(arguments)); save();
        }
        @SuppressWarnings("unchecked") private Map<String, Object> map(String key) {
            return (Map<String, Object>) data.computeIfAbsent(key, k -> new LinkedHashMap<>());
        }
        public synchronized Map<String, Object> summary() {
            var summary = new LinkedHashMap<>(data);
            summary.put("job_id", id());
            summary.remove("arguments"); summary.remove("identities"); summary.remove("checkpoints");
            summary.put("completed_units", map("checkpoints").size());
            summary.put("uncertain_units", map("pending").size()); summary.remove("pending");
            summary.put("manifest", directory.resolve("manifest.json").toString());
            if (Files.exists(directory.resolve("result.json"))) summary.put("result_file", directory.resolve("result.json").toString());
            return summary;
        }
        public synchronized void validateIdentity(String key, Map<String, Object> identity) throws IOException {
            Object prior = map("identities").get(key);
            if (prior != null && !BsimSupport.JSON.readTree(BsimSupport.JSON.writeValueAsBytes(prior)).equals(BsimSupport.JSON.readTree(BsimSupport.JSON.writeValueAsBytes(identity))))
                throw new IOException("Resume input changed: " + key + "; create a new job");
            if (prior == null) { map("identities").put(key, identity); save(); }
        }
        public synchronized void begin(String key, Map<String, Object> evidence) throws IOException {
            if (completed(key) != null) throw new IllegalStateException("Unit already completed: " + key);
            map("pending").put(key, evidence); save();
        }
        public synchronized void checkpoint(String key, Map<String, Object> result) throws IOException {
            String file = "unit-" + BsimSupport.digest(key) + ".json";
            BsimSupport.atomicJson(directory.resolve(file), result);
            map("checkpoints").put(key, Map.of("checkpoint_file", file)); map("pending").remove(key); save();
        }
        @SuppressWarnings("unchecked") public synchronized Map<String, Object> completed(String key) {
            Object value = map("checkpoints").get(key);
            if (value instanceof Map<?, ?> reference && reference.get("checkpoint_file") instanceof String file) {
                if (!file.matches("unit-[0-9a-f]+\\.json")) throw new IllegalStateException("Invalid checkpoint file");
                try { return BsimSupport.readJson(directory.resolve(file)); }
                catch (IOException e) { throw new java.io.UncheckedIOException(e); }
            }
            return value instanceof Map ? new LinkedHashMap<>((Map<String, Object>) value) : null;
        }
        @SuppressWarnings("unchecked") public synchronized Map<String, Object> pending(String key) {
            Object value = map("pending").get(key);
            return value instanceof Map ? new LinkedHashMap<>((Map<String, Object>) value) : null;
        }
        public synchronized void finish(Map<String, Object> result) throws IOException {
            var metadata = new LinkedHashMap<>(result);
            var lists = new LinkedHashMap<String, Object>();
            for (var entry : result.entrySet()) if (entry.getValue() instanceof List<?> rows) {
                String file = "rows-" + BsimSupport.digest(entry.getKey()) + ".jsonl";
                Path temporary = Files.createTempFile(directory, ".rows-", ".tmp");
                try {
                    try (var writer = Files.newBufferedWriter(temporary)) {
                        for (Object row : rows) { writer.write(BsimSupport.JSON.writeValueAsString(row)); writer.newLine(); }
                    }
                    Files.move(temporary, directory.resolve(file), StandardCopyOption.REPLACE_EXISTING);
                } finally { Files.deleteIfExists(temporary); }
                lists.put(entry.getKey(), Map.of("file", file, "total", rows.size())); metadata.remove(entry.getKey());
            }
            metadata.put("_list_files", lists);
            BsimSupport.atomicJson(directory.resolve("result.json"), metadata); transition("COMPLETED", null);
        }
        public synchronized Map<String, Object> results(String field, int offset, int limit) throws IOException {
            Path path = directory.resolve("result.json");
            if (!Files.exists(path)) {
                var keys = new ArrayList<>(map("checkpoints").keySet());
                var rows = new ArrayList<Map<String, Object>>();
                for (String key : keys.stream().skip(offset).limit(limit).toList()) rows.add(Map.of("unit", key, "result", completed(key)));
                return Map.of("job_id", id(), "status", status(), "checkpoints", rows, "offset", offset, "total", keys.size());
            }
            Map<String, Object> result = BsimSupport.readJson(path);
            if (result.remove("_list_files") instanceof Map<?, ?> lists) {
                Map<String, Object> totals = new LinkedHashMap<>();
                for (var entry : lists.entrySet()) {
                    if (field != null && !field.equals(entry.getKey())) continue;
                    var reference = (Map<?, ?>) entry.getValue();
                    String file = String.valueOf(reference.get("file"));
                    if (!file.matches("rows-[0-9a-f]+\\.jsonl")) throw new IOException("Invalid result file");
                    List<Object> rows = new ArrayList<>();
                    try (var stream = Files.lines(directory.resolve(file))) {
                        for (String line : stream.skip(offset).limit(limit).toList()) rows.add(BsimSupport.JSON.readValue(line, Object.class));
                    }
                    long total = ((Number) reference.get("total")).longValue();
                    if (field != null) return Map.of("job_id", id(), "field", field, "total", total,
                        "offset", offset, "rows", rows, "truncated", (long)offset + limit < total);
                    result.put(entry.getKey().toString(), rows); totals.put(entry.getKey().toString(), total);
                }
                if (field != null) throw new IllegalArgumentException("Result field is not a list: " + field);
                result.put("result_totals", totals); result.put("result_offset", offset); result.put("result_limit", limit);
                return result;
            }
            if (field == null) return page(result, offset, limit);
            Object value = result.get(field);
            if (!(value instanceof List<?> list)) throw new IllegalArgumentException("Result field is not a list: " + field);
            return Map.of("job_id", id(), "field", field, "total", list.size(), "offset", offset,
                "rows", list.subList(Math.min(offset, list.size()), Math.min(list.size(), (int)Math.min(Integer.MAX_VALUE, (long)offset + limit))),
                "truncated", (long)offset + limit < list.size());
        }
        public synchronized void transition(String status, String message) throws IOException {
            data.put("status", status); data.put("updated_at", Instant.now().toString());
            if (message != null) data.put("message", BsimSupport.redact(message)); else data.remove("message"); save();
        }
        public synchronized void note(String message) throws IOException { data.put("message", BsimSupport.redact(message)); save(); }
        private synchronized void save() throws IOException { BsimSupport.atomicJson(directory.resolve("manifest.json"), data); }
    }
    static Map<String, Object> page(Map<String, Object> result, int offset, int limit) {
        var copy = new LinkedHashMap<>(result);
        var totals = new LinkedHashMap<String, Object>();
        for (var entry : result.entrySet()) if (entry.getValue() instanceof List<?> list) {
            int from = Math.min(offset, list.size()), to = (int)Math.min(list.size(), (long)from + limit);
            copy.put(entry.getKey(), list.subList(from, to)); totals.put(entry.getKey(), list.size());
        }
        if (!totals.isEmpty()) { copy.put("result_totals", totals); copy.put("result_offset", offset); copy.put("result_limit", limit); }
        return copy;
    }
}
