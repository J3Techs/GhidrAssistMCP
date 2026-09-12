package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskMonitor;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class ProjectFilesTool implements McpTool {
    private final Supplier<Project> projects;
    public ProjectFilesTool() { this(ProjectToolSupport::activeProject); }
    ProjectFilesTool(Supplier<Project> projects) { this.projects = projects; }
    @Override public boolean isLongRunning() { return true; }

    @Override
    public String getName() {
        return "project_files";
    }

    @Override
    public String getDescription() {
        return "List, create_folder, copy, move, rename or delete files/folders in the active Ghidra project. " +
            "Copy/move use destination_folder; rename uses name. New mutations support dry_run and never overwrite entries. " +
            "Deletion requires confirm=true and removes Ghidra project database entries, not original imported files.";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isDestructive() {
        return true;
    }

    @Override
    public boolean isIdempotent() {
        return false;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "delete", "create_folder", "copy", "move", "rename")
                )),
                Map.entry("path", Map.of(
                    "type", "string",
                    "description", "Exact project source path, or full new folder path for create_folder"
                )),
                Map.entry("destination_folder", Map.of("type", "string", "description", "Existing project folder for copy/move")),
                Map.entry("name", Map.of("type", "string", "description", "New leaf name for rename")),
                Map.entry("dry_run", Map.of("type", "boolean", "default", false)),
                Map.entry("folder", Map.of(
                    "type", "string",
                    "description", "Project folder to list. Default: '/'"
                )),
                Map.entry("target_type", Map.of(
                    "type", "string",
                    "description", "For delete: file, folder, or auto. Default: auto",
                    "enum", List.of("auto", "file", "folder"),
                    "default", "auto"
                )),
                Map.entry("recursive", Map.of(
                    "type", "boolean",
                    "description", "For list/delete folder: include/delete children recursively. Default: false",
                    "default", false
                )),
                Map.entry("confirm", Map.of(
                    "type", "boolean",
                    "description", "Required true for action='delete'"
                ))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, ghidra.program.model.listing.Program currentProgram) {
        return textResult("This tool requires backend context (project access).");
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments,
                                            ghidra.program.model.listing.Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        return perform(arguments, backend, TaskMonitor.DUMMY);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments,
            ghidra.program.model.listing.Program currentProgram, GhidrAssistMCPBackend backend, McpTask task) {
        return perform(arguments, backend, new McpTaskMonitor(task, 0, 100, "Project files"));
    }

    private McpSchema.CallToolResult perform(Map<String, Object> arguments,
            GhidrAssistMCPBackend backend, TaskMonitor monitor) {
        Project project = backend != null && backend.isHeadlessSession() ? backend.getProject() : getProject();
        if (project == null) {
            return textResult("No Ghidra project is open.");
        }
        try { ProjectToolSupport.verifyProject(arguments, project); }
        catch (Exception e) { return ProjectToolSupport.error(e.getMessage()); }

        String action = (String) arguments.get("action");
        if (action == null || action.isBlank()) {
            return ProjectToolSupport.error("action is required: list, delete, create_folder, copy, move or rename.");
        }

        DomainFolder root = project.getProjectData().getRootFolder();
        return switch (action.trim().toLowerCase()) {
            case "list" -> list(root, arguments);
            case "delete" -> delete(root, arguments, backend, monitor);
            case "create_folder", "copy", "move", "rename" -> manage(root, action.trim().toLowerCase(), arguments, backend, monitor);
            default -> ProjectToolSupport.error("Invalid action: " + action);
        };
    }

    private Project getProject() {
        return projects.get();
    }

    private McpSchema.CallToolResult manage(DomainFolder root, String action, Map<String, Object> args,
                                           GhidrAssistMCPBackend backend, TaskMonitor monitor) {
        try {
            String path = ProjectToolSupport.path(ProjectToolSupport.required(args, "path"));
            if (path.equals("/")) return ProjectToolSupport.error("Cannot mutate the project root");
            DomainFile file = ProjectToolSupport.file(root, path);
            DomainFolder folder = ProjectToolSupport.folder(root, path);
            boolean preview = Boolean.TRUE.equals(args.get("dry_run"));
            String name;
            DomainFolder destination;
            if (action.equals("create_folder")) {
                int slash = path.lastIndexOf('/');
                name = path.substring(slash + 1);
                destination = ProjectToolSupport.folder(root, slash == 0 ? "/" : path.substring(0, slash));
            } else {
                if (file == null && folder == null) return ProjectToolSupport.error("Project entry not found: " + path);
                if (action.equals("rename")) {
                    name = ProjectToolSupport.required(args, "name");
                    if (name.contains("/") || name.contains("\\") || name.equals(".") || name.equals("..")) {
                        return ProjectToolSupport.error("name must be a single project entry name");
                    }
                    destination = file != null ? file.getParent() : folder.getParent();
                } else {
                    name = file != null ? file.getName() : folder.getName();
                    destination = ProjectToolSupport.folder(root, ProjectToolSupport.required(args, "destination_folder"));
                }
            }
            if (destination == null) return ProjectToolSupport.error("Destination folder does not exist");
            if (destination.isLinked()) return ProjectToolSupport.error("Destination must be a local project folder");
            if (destination.getFile(name) != null || destination.getFolder(name) != null) {
                return ProjectToolSupport.error("Destination already exists; no overwrite performed");
            }
            if (folder != null && folder.isSameOrAncestor(destination)) {
                return ProjectToolSupport.error("Cannot copy/move a folder into itself or a descendant");
            }
            if (file != null && (file.isBusy() || file.isChanged())) {
                return ProjectToolSupport.error("Finish active work and save_program before moving/copying this file");
            }
            if (folder != null) ensureStable(folder, monitor);
            String target = (destination.getPathname().equals("/") ? "" : destination.getPathname()) + "/" + name;
            if (preview) return ProjectToolSupport.result(Map.of("action", action, "source", path,
                "destination", target, "dry_run", true));
            String result;
            monitor.checkCancelled();
            switch (action) {
                case "create_folder" -> result = destination.createFolder(name).getPathname();
                case "rename" -> result = file != null ? file.setName(name).getPathname() : folder.setName(name).getPathname();
                case "move" -> result = file != null ? file.moveTo(destination).getPathname() : folder.moveTo(destination).getPathname();
                case "copy" -> result = file != null ? file.copyTo(destination, monitor).getPathname() : folder.copyTo(destination, monitor).getPathname();
                default -> throw new IllegalArgumentException("Unknown operation");
            }
            if (backend != null) backend.clearCache();
            return ProjectToolSupport.result(Map.of("action", action, "source", path, "destination", result, "completed", true));
        } catch (Exception e) {
            return ProjectToolSupport.error(e.getClass().getSimpleName() + ": " + e.getMessage() +
                ". Ghidra may require the entry to be closed or checked in first. Inspect the destination if a folder operation was interrupted.");
        }
    }

    private void ensureStable(DomainFolder folder, TaskMonitor monitor) throws Exception {
        var pending = new java.util.ArrayDeque<DomainFolder>();
        pending.add(folder);
        int entries = 0;
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            var current = pending.removeFirst();
            if (++entries > 10000) throw new IllegalArgumentException("Folder operation exceeds 10000 entries; use smaller subfolders");
            if (current.isLinked()) throw new IllegalArgumentException("Linked folders are not supported for mutations");
            for (DomainFile file : current.getFiles()) {
                monitor.checkCancelled();
                if (++entries > 10000) throw new IllegalArgumentException("Folder operation exceeds 10000 entries; use smaller subfolders");
                if (file.isBusy() || file.isChanged() || file.isOpen()) throw new IllegalArgumentException("Unsaved, busy, or open file: " + file.getPathname());
            }
            for (DomainFolder child : current.getFolders()) {
                if (pending.size() + entries >= 10000) throw new IllegalArgumentException("Folder operation exceeds 10000 entries; use smaller subfolders");
                pending.addLast(child);
            }
        }
    }

    private McpSchema.CallToolResult list(DomainFolder root, Map<String, Object> arguments) {
        String folderPath = stringArg(arguments.get("folder"), "/");
        boolean recursive = Boolean.TRUE.equals(arguments.get("recursive"));

        DomainFolder folder = resolveFolder(root, folderPath);
        if (folder == null) {
            return textResult("Folder not found: " + folderPath);
        }

        List<String> rows = new ArrayList<>();
        collect(folder, recursive, rows);
        rows.sort(String.CASE_INSENSITIVE_ORDER);

        StringBuilder sb = new StringBuilder();
        sb.append("Project entries under ").append(folder.getPathname()).append("\n\n");
        for (String row : rows) {
            sb.append(row).append("\n");
        }
        sb.append("\nTotal: ").append(rows.size()).append(" entr").append(rows.size() == 1 ? "y" : "ies");
        return textResult(sb.toString());
    }

    private McpSchema.CallToolResult delete(DomainFolder root, Map<String, Object> arguments,
                                            GhidrAssistMCPBackend backend, TaskMonitor monitor) {
        boolean dryRun = Boolean.TRUE.equals(arguments.get("dry_run"));
        if (!dryRun && !Boolean.TRUE.equals(arguments.get("confirm"))) {
            return textResult("Refusing to delete. Pass confirm=true to delete a project file or folder.");
        }

        String path = stringArg(arguments.get("path"), null);
        if (path == null || path.isBlank()) {
            return textResult("path is required for action='delete'.");
        }

        String normalizedPath = normalizePath(path);
        if ("/".equals(normalizedPath)) {
            return textResult("Refusing to delete the project root folder.");
        }

        String targetType = stringArg(arguments.get("target_type"), "auto").toLowerCase();
        boolean recursive = Boolean.TRUE.equals(arguments.get("recursive"));
        List<String> completed = new ArrayList<>();

        try {
            if ("file".equals(targetType) || "auto".equals(targetType)) {
                DomainFile file = resolveFile(root, normalizedPath);
                if (file != null) {
                    String deletedPath = file.getPathname();
                    monitor.checkCancelled();
                    if (file.isBusy() || file.isChanged() || file.isOpen()) return ProjectToolSupport.error("File is busy, open, or has unsaved changes: " + deletedPath);
                    if (dryRun) return ProjectToolSupport.result(Map.of("action", "delete", "target", deletedPath, "target_type", "file", "dry_run", true));
                    file.delete();
                    completed.add(deletedPath);
                    if (backend != null) {
                        backend.clearCache();
                    }
                    return textResult("Deleted project file: " + deletedPath);
                }
                if ("file".equals(targetType)) {
                    return textResult("Project file not found: " + normalizedPath);
                }
            }

            if ("folder".equals(targetType) || "auto".equals(targetType)) {
                DomainFolder folder = resolveFolder(root, normalizedPath);
                if (folder == null) {
                    return textResult("Project folder not found: " + normalizedPath);
                }
                ensureStable(folder, monitor);
                if (!recursive && !folder.isEmpty()) return ProjectToolSupport.error("Folder is not empty. Pass recursive=true to delete children.");
                List<String> planned = new ArrayList<>();
                collect(folder, recursive, planned);
                if (dryRun) return ProjectToolSupport.result(Map.of("action", "delete", "target", normalizedPath,
                    "target_type", "folder", "recursive", recursive, "entries", planned, "dry_run", true));
                int deleted = deleteFolder(folder, recursive, monitor, completed);
                if (backend != null) {
                    backend.clearCache();
                }
                return textResult("Deleted project folder: " + normalizedPath +
                    " (" + deleted + " entr" + (deleted == 1 ? "y" : "ies") + ")");
            }

            return textResult("Invalid target_type: " + targetType + ". Use auto, file, or folder.");
        } catch (Exception e) {
            Msg.error(this, "Failed to delete project entry: " + normalizedPath, e);
            return ProjectToolSupport.result(Map.of("action", "delete", "target", normalizedPath,
                "completed", completed, "failed", normalizedPath, "partial", !completed.isEmpty(),
                "error", e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()),
                "message", "If the file is open in CodeBrowser, close it and try again."), true);
        }
    }

    private int deleteFolder(DomainFolder folder, boolean recursive, TaskMonitor monitor, List<String> completed) throws Exception {
        if (!recursive && !folder.isEmpty()) {
            throw new IllegalArgumentException("Folder is not empty. Pass recursive=true to delete children.");
        }

        int deleted = 0;
        if (recursive) {
            for (DomainFile file : folder.getFiles()) {
                monitor.checkCancelled();
                file.delete();
                completed.add(file.getPathname());
                deleted++;
            }

            List<DomainFolder> children = new ArrayList<>(List.of(folder.getFolders()));
            children.sort(Comparator.comparing(DomainFolder::getPathname).reversed());
            for (DomainFolder child : children) {
                deleted += deleteFolder(child, true, monitor, completed);
            }
        }

        folder.delete();
        completed.add(folder.getPathname());
        return deleted + 1;
    }

    private void collect(DomainFolder folder, boolean recursive, List<String> rows) {
        for (DomainFolder child : folder.getFolders()) {
            rows.add("[folder] " + child.getPathname());
            if (recursive) {
                collect(child, true, rows);
            }
        }
        for (DomainFile file : folder.getFiles()) {
            rows.add("[file]   " + file.getPathname() + " (" + file.getContentType() + ")");
        }
    }

    private DomainFolder resolveFolder(DomainFolder root, String path) {
        String normalized = normalizePath(path);
        if ("/".equals(normalized)) {
            return root;
        }

        DomainFolder folder = root;
        for (String part : normalized.substring(1).split("/")) {
            if (part.isEmpty()) {
                continue;
            }
            folder = folder.getFolder(part);
            if (folder == null) {
                return null;
            }
        }
        return folder;
    }

    private DomainFile resolveFile(DomainFolder root, String path) {
        String normalized = normalizePath(path);
        int slash = normalized.lastIndexOf('/');
        String folderPath = slash <= 0 ? "/" : normalized.substring(0, slash);
        String fileName = normalized.substring(slash + 1);
        DomainFolder folder = resolveFolder(root, folderPath);
        return folder != null ? folder.getFile(fileName) : null;
    }

    private String normalizePath(String path) {
        String normalized = path != null ? path.trim().replace('\\', '/') : "/";
        if (normalized.isEmpty()) {
            normalized = "/";
        }
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        while (normalized.length() > 1 && normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String stringArg(Object value, String defaultValue) {
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        return defaultValue;
    }

    private McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
