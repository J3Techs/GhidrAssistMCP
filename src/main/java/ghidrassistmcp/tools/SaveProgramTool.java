package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Saves the program database, without closing it or checking it into a repository. */
public class SaveProgramTool implements McpTool {
    private final Supplier<Project> projects;
    public SaveProgramTool() { this(ProjectToolSupport::activeProject); }
    SaveProgramTool(Supplier<Project> projects) { this.projects = projects; }
    @Override public String getName() { return "save_program"; }
    @Override public String getDescription() {
        return "Save an open program without closing it. Uses program_name/current program or an exact project path. " +
            "Refuses active transactions, busy or read-only files; reports whether unsaved changes remain. " +
            "Does not check in, checkout, force unlock, or save FrontEnd session metadata.";
    }
    @Override public boolean isReadOnly() { return false; }
    @Override public boolean isIdempotent() { return true; }
    @Override public boolean isLongRunning() { return true; }
    @Override public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "path", Map.of("type", "string", "description", "Optional exact open project file path."),
            "paths", Map.of("type", "array", "items", Map.of("type", "string"),
                "description", "Optional bounded explicit list of exact open project paths.")), List.of(), null, null, null);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program) {
        return save(args, program, TaskMonitor.DUMMY);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program, GhidrAssistMCPBackend backend) {
        Map<String,Object> effective = new java.util.HashMap<>(args);
        if (backend != null && backend.isHeadlessSession()) effective.put("__backend_project", backend.getProject());
        return save(effective, program, TaskMonitor.DUMMY);
    }
    @Override public McpSchema.CallToolResult execute(Map<String, Object> args, Program program,
            GhidrAssistMCPBackend backend, McpTask task) {
        Map<String,Object> effective = new java.util.HashMap<>(args);
        if (backend != null && backend.isHeadlessSession()) effective.put("__backend_project", backend.getProject());
        return save(effective, program, new McpTaskMonitor(task, 0, 100, "Saving program"));
    }
    private McpSchema.CallToolResult save(Map<String, Object> args, Program program, TaskMonitor monitor) {
        if (args.containsKey("path") && args.containsKey("paths")) return ProjectToolSupport.error("Specify path or paths, not both");
        Object rawPaths = args.get("paths");
        if (args.containsKey("paths") && !(rawPaths instanceof List<?>)) return ProjectToolSupport.error("paths must be an array of strings");
        if (rawPaths instanceof List<?> paths) {
            if (paths.isEmpty() || paths.size() > 100) return ProjectToolSupport.error("paths must contain 1 to 100 entries");
            List<Map<String, Object>> outcomes = new java.util.ArrayList<>();
            boolean failed = false;
            for (int index = 0; index < paths.size(); index++) {
                Object raw = paths.get(index);
                if (monitor.isCancelled()) {
                    for (int remaining = index; remaining < paths.size(); remaining++) outcomes.add(Map.of("path", String.valueOf(paths.get(remaining)), "is_error", true, "not_attempted", true, "error", "Batch cancelled"));
                    failed = true;
                    break;
                }
                if (!(raw instanceof String path) || path.isBlank()) {
                    outcomes.add(Map.of("saved", false, "is_error", true, "error", "Each paths entry must be a nonblank string"));
                    failed = true;
                    continue;
                }
                Map<String,Object> oneArgs = new java.util.HashMap<>(); oneArgs.put("path", path);
                if (args.containsKey("__project_identity")) oneArgs.put("__project_identity", args.get("__project_identity"));
                if (args.containsKey("__backend_project")) oneArgs.put("__backend_project", args.get("__backend_project"));
                McpSchema.CallToolResult one = saveOne(oneArgs, program, monitor);
                failed |= Boolean.TRUE.equals(one.isError());
                outcomes.add(Map.of("path", path, "is_error", Boolean.TRUE.equals(one.isError()),
                    "result", one.structuredContent() == null ? one.content() : one.structuredContent()));
            }
            return ProjectToolSupport.result(Map.of("count", outcomes.size(), "all_succeeded", !failed, "results", outcomes), failed);
        }
        return saveOne(args, program, monitor);
    }

    private McpSchema.CallToolResult saveOne(Map<String, Object> args, Program program, TaskMonitor monitor) {
        Object consumer = new Object();
        DomainObject opened = null;
        try {
            Project boundProject = args.get("__backend_project") instanceof Project p ? p : (args.containsKey("__project_identity") ? projects.get() : null);
            if (args.containsKey("__project_identity")) ProjectToolSupport.verifyProject(args, boundProject);
            DomainFile file;
            if (args.containsKey("path")) {
                Project project = boundProject != null ? boundProject : projects.get();
                if (project == null) return ProjectToolSupport.error("No active Ghidra project");
                file = ProjectToolSupport.file(project.getProjectData().getRootFolder(),
                    ProjectToolSupport.required(args, "path"));
            } else {
                file = program == null || program.isClosed() ? null : program.getDomainFile();
            }
            if (file == null) return ProjectToolSupport.error("No target program file found");
            if (!file.isOpen()) return ProjectToolSupport.error("Program must already be open: " + file.getPathname());
            opened = file.getOpenedDomainObject(consumer);
            if (!(opened instanceof Program) || opened.isClosed()) return ProjectToolSupport.error("Target is not an open program");
            if (file.isBusy() || opened.getCurrentTransactionInfo() != null) {
                return ProjectToolSupport.error("Program has an active transaction or is busy; retry after it finishes");
            }
            boolean changed = opened.isChanged();
            if (!changed) return ProjectToolSupport.result(Map.of("path", file.getPathname(),
                "saved", false, "no_changes", true, "dirty_after", false));
            if (!file.canSave() || file.isReadOnly() || !opened.canSave() || !opened.isChangeable()) {
                return ProjectToolSupport.error("Program is not writable/saveable; checkout may be required");
            }
            monitor.checkCancelled();
            file.save(monitor);
            if (opened.isChanged()) return ProjectToolSupport.error("Save returned, but unsaved changes remain; program may have changed concurrently");
            return ProjectToolSupport.result(Map.of("path", file.getPathname(), "saved", true,
                "dirty_before", changed, "dirty_after", false, "open", file.isOpen()));
        } catch (Exception e) {
            return ProjectToolSupport.error(e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            if (opened != null) opened.release(consumer);
        }
    }
}
