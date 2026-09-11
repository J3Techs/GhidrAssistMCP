package ghidrassistmcp.bsim;

import java.io.IOException;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;

/** Per-operation program ownership, database access and durable checkpoints. */
public final class BsimContext implements AutoCloseable {
    private final List<Runnable> cleanup = new ArrayList<>();
    private final Program current;
    private final GhidrAssistMCPBackend backend;
    private final BsimConnections connections;
    private final Path artifacts;
    private final BsimJobs.Job job;
    public BsimContext(Program current, GhidrAssistMCPBackend backend, BsimConnections connections,
            Path artifacts, BsimJobs.Job job) {
        this.current = current != null && !current.isClosed() ? current : null; this.backend = backend; this.connections = connections;
        this.artifacts = artifacts; this.job = job;
    }
    public Program program() { return current; }
    public GhidrAssistMCPBackend backend() { return backend; }
    public BsimConnections connections() { return connections; }
    public Path artifacts() { return artifacts; }
    public String jobId() { return job == null ? "interactive" : job.id(); }
    public FunctionDatabase database(Map<String, Object> args) throws Exception {
        FunctionDatabase database = connections.open(args, true);
        if (job != null) {
            try {
                var info = database.getInfo();
                Map<String, Object> identity = Map.of("url", BsimSupport.redact(database.getURLString()),
                    "signature_config", BsimSupport.digest(BsimSupport.vectorConfiguration(database.getLSHVectorFactory())),
                    "layout", info.layout_version);
                String selector = BsimSupport.text(args, "database", BsimSupport.text(args, "profile_id",
                    BsimSupport.text(args, "database_url", database.getURLString())));
                job.validateIdentity("database:" + selector, identity);
            } catch (Exception e) { database.close(); throw e; }
        }
        return database;
    }
    public void checkpoint(String key, Map<String, Object> result) throws IOException {
        if (job != null) job.checkpoint(key, result);
    }
    public Map<String, Object> completed(String key) { return job == null ? null : job.completed(key); }
    public void begin(String key, Map<String, Object> evidence) throws IOException { if (job != null) job.begin(key, evidence); }
    public Map<String, Object> pending(String key) { return job == null ? null : job.pending(key); }
    public void validateIdentity(String key, Map<String, Object> identity) throws IOException { if (job != null) job.validateIdentity(key, identity); }
    /** Resolve a folder/current-program selection once, before durable work is queued. */
    public Map<String, Object> snapshotPrograms(Map<String, Object> args, TaskMonitor monitor) throws Exception {
        var handles = resolvePrograms(args, monitor);
        var paths = new ArrayList<String>();
        for (var handle : handles) {
            if (handle.file.isOpen()) { BsimSupport.requireSaved(handle.program()); }
            URL url = handle.file.getSharedProjectURL(null);
            if (url == null) url = handle.file.getLocalProjectURL(null);
            if (url == null) throw new IllegalArgumentException("Durable work requires saved project programs");
            paths.add(url.toString());
            validateIdentity("file:" + handle.identity(), handle.fileIdentity());
        }
        Map<String, Object> frozen = new LinkedHashMap<>(args);
        frozen.remove("project_folder"); frozen.remove("program"); frozen.remove("project_url");
        frozen.put("programs", paths);
        return frozen;
    }
    public void validateProgramFiles(Map<String, Object> args, TaskMonitor monitor) throws Exception {
        for (var handle : resolvePrograms(args, monitor)) {
            try (handle) {
                validateIdentity("file:" + handle.identity(), handle.fileIdentity());
                if (handle.file.isOpen()) BsimSupport.requireSaved(handle.program());
            }
        }
    }
    public List<ProgramHandle> resolvePrograms(Map<String, Object> args, TaskMonitor monitor) throws Exception {
        return resolvePrograms(args, monitor, false);
    }
    public List<ProgramHandle> resolvePrograms(Map<String, Object> args, TaskMonitor monitor, boolean forWrite) throws Exception {
        Project project = activeProject();
        ProjectData data = project != null ? project.getProjectData() : current != null && current.getDomainFile().getParent() != null
            ? current.getDomainFile().getParent().getProjectData() : null;
        if (args.containsKey("project_url")) {
            URL url = new URL(BsimSupport.text(args, "project_url"));
            data = projectData(project, data, url);
        }
        if (args.containsKey("program") && !args.containsKey("programs")) {
            args = new LinkedHashMap<>(args);
            args.put("programs", List.of(BsimSupport.text(args, "program")));
        }
        LinkedHashMap<String, ProgramHandle> result = new LinkedHashMap<>();
        try {
            if (args.containsKey("project_folder")) {
                if (data == null) throw new IllegalArgumentException("No active project");
                DomainFolder folder = data.getFolder(projectPath(BsimSupport.text(args, "project_folder")));
                if (folder == null) throw new IllegalArgumentException("Project folder not found");
                var pending = new ArrayDeque<DomainFolder>(); pending.add(folder);
                int visited = 0;
                while (!pending.isEmpty()) {
                    monitor.checkCancelled();
                    if (++visited > 100000) throw new IllegalArgumentException("Project traversal exceeds 100000 folders");
                    DomainFolder next = pending.removeFirst();
                    if (next.isLinked()) continue;
                    for (DomainFile file : next.getFiles()) {
                        if (Program.class.isAssignableFrom(file.getDomainObjectClass())) add(result, new ProgramHandle(file, null, monitor, forWrite));
                    }
                    if (BsimSupport.bool(args, "recursive", true)) Collections.addAll(pending, next.getFolders());
                }
            } else if (args.containsKey("programs")) {
                if (!(args.get("programs") instanceof List<?> names) || names.isEmpty()) throw new IllegalArgumentException("programs must be a nonempty array");
                for (Object value : names) {
                    monitor.checkCancelled();
                    if (!(value instanceof String name)) throw new IllegalArgumentException("programs entries must be names or exact project paths");
                    if (GhidraURL.isGhidraURL(name)) {
                        URL url = new URL(name);
                        ProjectData selectedData = projectData(project, data, GhidraURL.getProjectURL(url));
                        DomainFile file = selectedData.getFile(GhidraURL.getProjectPathname(url));
                        if (file == null) throw new IllegalArgumentException("Program not found: " + name);
                        add(result, new ProgramHandle(file, null, monitor, forWrite));
                        continue;
                    }
                    Program open = args.containsKey("project_url") ? null : findOpen(name);
                    DomainFile file = open != null ? open.getDomainFile() : data == null ? null : data.getFile(projectPath(name));
                    if (file == null) throw new IllegalArgumentException("Program not found: " + name);
                    add(result, new ProgramHandle(file, open, monitor, forWrite));
                }
            } else {
                if (current == null || current.isClosed()) throw new IllegalArgumentException("No current program; specify programs or project_folder");
                add(result, new ProgramHandle(current.getDomainFile(), current, monitor, forWrite));
            }
            return new ArrayList<>(result.values());
        } catch (Exception e) { for (ProgramHandle handle : result.values()) handle.close(); throw e; }
    }
    private ProjectData projectData(Project project, ProjectData fallback, URL url) throws Exception {
        if (fallback != null && (GhidraURL.makeURL(fallback.getProjectLocator()).equals(url)
                || current != null && current.getDomainFile().getSharedProjectURL(null) != null
                    && GhidraURL.getProjectURL(current.getDomainFile().getSharedProjectURL(null)).equals(url))) return fallback;
        if (project == null) {
            var connection = (ghidra.framework.protocol.ghidra.GhidraURLConnection) url.openConnection();
            connection.setReadOnly(true);
            ProjectData opened = connection.getProjectData();
            if (opened == null) throw new IllegalArgumentException("Project URL is unavailable");
            cleanup.add(opened::close);
            return opened;
        }
        ProjectData data = project.getProjectData(url);
        if (data == null) {
            data = project.addProjectView(url, false);
            cleanup.add(() -> project.removeProjectView(url));
        }
        return data;
    }
    private void add(Map<String, ProgramHandle> result, ProgramHandle handle) {
        result.putIfAbsent(handle.identity(), handle);
        cleanup.add(handle::close);
        if (result.size() > 100000) throw new IllegalArgumentException("At most 100000 programs per job");
    }
    @Override public void close() {
        for (int i = cleanup.size() - 1; i >= 0; i--) cleanup.get(i).run();
        cleanup.clear();
    }
    private Program findOpen(String name) {
        var programs = backend != null ? backend.getAllOpenPrograms() : current == null ? List.<Program>of() : List.of(current);
        var matches = programs.stream().filter(p -> !p.isClosed() && (p.getName().equals(name) || p.getDomainFile().getPathname().equals(name))).toList();
        if (matches.size() > 1) throw new IllegalArgumentException("Ambiguous program name; use exact project path: " + name);
        return matches.isEmpty() ? null : matches.get(0);
    }
    private static Project activeProject() {
        var tool = GhidrAssistMCPManager.getInstance().getActiveTool();
        return tool == null ? ghidra.framework.main.AppInfo.getActiveProject() : tool.getProject();
    }
    private static String projectPath(String value) {
        String path = value.replace('\\', '/');
        if (path.matches("^[A-Za-z]:.*") || path.startsWith("//")) throw new IllegalArgumentException("Use a Ghidra project path");
        for (String component : path.split("/")) if (component.equals("..") || component.equals(".")) throw new IllegalArgumentException("Invalid project path");
        return path.startsWith("/") ? path : "/" + path;
    }
    public final class ProgramHandle implements AutoCloseable {
        private final DomainFile file;
        private Program program;
        private final TaskMonitor monitor;
        private final boolean write;
        private final boolean initiallyOpen;
        private final Object consumer = new Object();
        private boolean acquired;
        ProgramHandle(DomainFile file, Program open, TaskMonitor monitor, boolean write) {
            this.file = file; this.program = open; this.monitor = monitor; this.write = write;
            this.initiallyOpen = open != null || file.isOpen();
        }
        public String identity() {
            var url = file.getSharedProjectURL(null);
            if (url == null) url = file.getLocalProjectURL(null);
            return url != null ? url.toString() : file.getPathname() + "#" + file.getFileID();
        }
        public Program program() {
            try {
                monitor.checkCancelled();
                if (!acquired) {
                    if (job != null) job.validateIdentity("file:" + identity(), fileIdentity());
                    if (program != null) program.addConsumer(consumer);
                    else {
                        program = file.isOpen() ? (Program) file.getOpenedDomainObject(consumer) : null;
                        if (program == null) program = (Program) (write ? file.getDomainObject(consumer, false, false, monitor)
                            : file.getReadOnlyDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor));
                    }
                    acquired = true;
                    if (job != null) job.validateIdentity("program:" + identity(), Map.of("file_id", String.valueOf(file.getFileID()),
                        "modified", file.getLastModifiedTime(), "version", file.getVersion(),
                        "md5", String.valueOf(program.getExecutableMD5())));
                }
                return program;
            } catch (Exception e) { close(); throw new IllegalArgumentException("Cannot open program " + identity() + ": " + BsimSupport.redact(e.getMessage()), e); }
        }
        private Map<String, Object> fileIdentity() {
            return Map.of("file_id", String.valueOf(file.getFileID()), "modified", file.getLastModifiedTime(), "version", file.getVersion());
        }
        /** Transfer ownership to CodeBrowser before modifying a previously closed program. Saving stays explicit. */
        public void retainForReview() {
            Program target = program();
            if (!target.isChangeable() || file.isReadOnly()) throw new IllegalStateException("Program is read-only; checkout may be required");
            if (initiallyOpen) return;
            var tool = GhidrAssistMCPManager.getInstance().getActiveTool();
            var manager = tool == null ? null : tool.getService(ghidra.app.services.ProgramManager.class);
            if (manager == null) throw new IllegalStateException("Open the target in CodeBrowser before applying matches; unsaved changes need an owning tool");
            ghidra.util.SystemUtilities.runSwingNow(() -> manager.openProgram(target));
        }
        @Override public void close() { if (acquired) { acquired = false; program.release(consumer); program = null; } }
    }
}
