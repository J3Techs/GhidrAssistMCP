package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Version control of Ghidra project files through the configured repository. */
public class ProjectRepositoryTool implements McpTool {
    private final Supplier<Project> projects;
    public ProjectRepositoryTool() { this(ProjectToolSupport::activeProject); }
    ProjectRepositoryTool(Supplier<Project> projects) { this.projects = projects; }
    @Override public String getName() { return "project_repository"; }
    @Override public String getDescription() {
        return "Ghidra project version control: status, history, checkouts, checkout, add, checkin, undo_checkout. " +
            "Uses the project's configured repository and permissions. Save changes first; checkin/add require a comment. " +
            "Undo checkout requires confirm=true and always keeps a private .keep copy. No forced checkout or automatic conflict merge.";
    }
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isDestructive() { return true; }
    @Override public boolean isLongRunning() { return true; }
    @Override public boolean isOpenWorld() { return true; }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "action", Map.of("type", "string", "enum", List.of("status", "history", "checkouts", "checkout", "add", "checkin", "undo_checkout", "merge")),
            "path", Map.of("type", "string", "description", "Exact Ghidra project file path"),
            "paths", Map.of("type", "array", "items", Map.of("type", "string"), "description", "Bounded exact paths for batch status"),
            "folder", Map.of("type", "string", "description", "Folder to scan for bounded batch status"),
            "exclusive", Map.of("type", "boolean", "default", false),
            "comment", Map.of("type", "string", "description", "Required for add/checkin"),
            "keep_checked_out", Map.of("type", "boolean", "default", true),
            "confirm", Map.of("type", "boolean", "description", "Required true for undo_checkout")),
            List.of("action"), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return perform(args, TaskMonitor.DUMMY, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
            GhidrAssistMCPBackend backend, McpTask task) {
        McpSchema.CallToolResult result = perform(args, new McpTaskMonitor(task, 0, 100, "Repository"), backend);
        if (backend != null && !Boolean.TRUE.equals(result.isError())) backend.clearCache();
        return result;
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program, GhidrAssistMCPBackend backend) {
        McpSchema.CallToolResult result = perform(args, TaskMonitor.DUMMY, backend);
        if (backend != null && !Boolean.TRUE.equals(result.isError())) backend.clearCache();
        return result;
    }
    private McpSchema.CallToolResult perform(Map<String, Object> args, TaskMonitor monitor, GhidrAssistMCPBackend backend) {
        try {
            String action = ProjectToolSupport.required(args, "action").toLowerCase(Locale.ROOT);
            Project project = backend != null && backend.isHeadlessSession() ? backend.getProject() : projects.get();
            if (project == null) return ProjectToolSupport.error("No active Ghidra project");
            ProjectToolSupport.verifyProject(args, project);
            if (action.equals("status") && (args.containsKey("paths") || args.containsKey("folder"))) {
                return batchStatus(project, args, monitor);
            }
            if (!args.containsKey("path")) return ProjectToolSupport.error("path is required for action=" + action);
            DomainFile file = ProjectToolSupport.file(project.getProjectData().getRootFolder(), ProjectToolSupport.required(args, "path"));
            if (file == null) return ProjectToolSupport.error("Project file not found");
            if (action.equals("status")) return ProjectToolSupport.result(status(file));
            if (action.equals("history")) {
                var versions = new ArrayList<Map<String, Object>>();
                var history = file.getVersionHistory();
                if (history != null) for (var version : history) {
                    monitor.checkCancelled();
                    var row = new LinkedHashMap<String, Object>();
                    row.put("version", version.getVersion()); row.put("user", version.getUser());
                    row.put("created_ms", version.getCreateTime()); row.put("comment", version.getComment());
                    versions.add(row);
                }
                return ProjectToolSupport.result(Map.of("path", file.getPathname(), "versions", versions));
            }
            if (action.equals("checkouts")) {
                var checkouts = new ArrayList<Map<String, Object>>();
                var activeCheckouts = file.getCheckouts();
                if (activeCheckouts != null) for (var checkout : activeCheckouts) {
                    monitor.checkCancelled();
                    var row = new LinkedHashMap<String, Object>();
                    row.put("id", checkout.getCheckoutId()); row.put("user", checkout.getUser());
                    row.put("version", checkout.getCheckoutVersion()); row.put("type", checkout.getCheckoutType().toString());
                    row.put("checkout_ms", checkout.getCheckoutTime()); checkouts.add(row);
                }
                return ProjectToolSupport.result(Map.of("path", file.getPathname(), "checkouts", checkouts));
            }
            if (file.isBusy() || file.isChanged()) return ProjectToolSupport.error("Finish active work and save_program before repository mutations");
            monitor.checkCancelled();
            switch (action) {
                case "checkout" -> {
                    if (!file.isCheckedOut()) {
                        if (!file.canCheckout()) return ProjectToolSupport.error("File cannot be checked out in its current state");
                        if (!file.checkout(Boolean.TRUE.equals(args.get("exclusive")), monitor)) {
                            return ProjectToolSupport.error("Checkout denied; an exclusive checkout may conflict with another user");
                        }
                    } else if (Boolean.TRUE.equals(args.get("exclusive")) && !file.isCheckedOutExclusive()) {
                        return ProjectToolSupport.error("Already checked out non-exclusively; no automatic checkout upgrade performed");
                    }
                }
                case "add" -> {
                    String comment = ProjectToolSupport.required(args, "comment");
                    if (!file.canAddToRepository()) return ProjectToolSupport.error("File cannot be added to version control");
                    file.addToVersionControl(comment, !Boolean.FALSE.equals(args.get("keep_checked_out")), monitor);
                }
                case "checkin" -> {
                    String comment = ProjectToolSupport.required(args, "comment");
                    if (!file.canCheckin()) return ProjectToolSupport.error("No check-in is available in the current state");
                    if (file.canMerge()) return ProjectToolSupport.error("Repository updates need a Ghidra merge before check-in");
                    file.checkin(new CheckinHandler() {
                        @Override public String getComment() { return comment; }
                        @Override public boolean keepCheckedOut() { return !Boolean.FALSE.equals(args.get("keep_checked_out")); }
                        @Override public boolean createKeepFile() { return true; }
                    }, monitor);
                }
                case "undo_checkout" -> {
                    if (!Boolean.TRUE.equals(args.get("confirm"))) return ProjectToolSupport.error("undo_checkout requires confirm=true; local work is retained as a .keep copy");
                    if (!file.isCheckedOut()) return ProjectToolSupport.error("File is not checked out");
                    file.undoCheckout(true);
                }
                case "merge" -> {
                    if (!file.canMerge()) return ProjectToolSupport.error("No repository merge is pending for this file");
                    return ProjectToolSupport.result(Map.of("action", "merge", "path", file.getPathname(),
                        "status", "awaiting_user_resolution", "message", "Use Ghidra's native merge UI to resolve and apply repository changes, then retry status/checkin."));
                }
                default -> { return ProjectToolSupport.error("Unknown repository action: " + action); }
            }
            return ProjectToolSupport.result(Map.of("action", action, "completed", true, "status", status(file)));
        } catch (Exception e) {
            return ProjectToolSupport.error(e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
    private Map<String, Object> status(DomainFile file) {
        var result = new LinkedHashMap<String, Object>();
        result.put("path", file.getPathname()); result.put("file_id", file.getFileID());
        result.put("versioned", file.isVersioned()); result.put("checked_out", file.isCheckedOut());
        result.put("exclusive", file.isCheckedOutExclusive()); result.put("hijacked", file.isHijacked());
        result.put("version", file.getVersion()); result.put("latest_version", file.getLatestVersion());
        result.put("dirty", file.isChanged()); result.put("busy", file.isBusy()); result.put("open", file.isOpen());
        result.put("read_only", file.isReadOnly()); result.put("can_save", file.canSave());
        result.put("can_checkout", file.canCheckout()); result.put("can_checkin", file.canCheckin());
        result.put("can_add", file.canAddToRepository()); result.put("can_merge", file.canMerge());
        return result;
    }

    private McpSchema.CallToolResult batchStatus(Project project, Map<String, Object> args, TaskMonitor monitor) throws Exception {
        List<DomainFile> files = new ArrayList<>();
        Object raw = args.get("paths");
        if (args.containsKey("paths") && !(raw instanceof List<?>)) return ProjectToolSupport.error("paths must be an array of strings");
        if (raw instanceof List<?> paths) {
            if (paths.size() > 100) return ProjectToolSupport.error("Batch status is limited to 100 paths");
            for (Object value : paths) {
                if (!(value instanceof String path)) return ProjectToolSupport.error("Each paths entry must be a string");
                DomainFile file = ProjectToolSupport.file(project.getProjectData().getRootFolder(), path);
                if (file == null) return ProjectToolSupport.error("Project file not found: " + path);
                files.add(file);
            }
        } else {
            var folder = ProjectToolSupport.folder(project.getProjectData().getRootFolder(), String.valueOf(args.getOrDefault("folder", "/")));
            if (folder == null) return ProjectToolSupport.error("Project folder not found");
            var pending = new java.util.ArrayDeque<ghidra.framework.model.DomainFolder>(); pending.add(folder);
            int visited = 0;
            while (!pending.isEmpty()) {
                monitor.checkCancelled();
                var current = pending.removeFirst();
                if (++visited > 10000 || current.isLinked()) return ProjectToolSupport.error("Folder status exceeds 10000 entries or contains a linked folder");
                for (DomainFile file : current.getFiles()) { if (files.size() >= 100) return ProjectToolSupport.error("Batch status is limited to 100 files"); files.add(file); }
                for (var child : current.getFolders()) { if (++visited > 10000) return ProjectToolSupport.error("Folder status exceeds 10000 entries"); pending.add(child); }
            }
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (DomainFile file : files) { monitor.checkCancelled(); rows.add(status(file)); }
        return ProjectToolSupport.result(Map.of("count", rows.size(), "statuses", rows));
    }
}
