/*
 * MCP tool for opening an existing program from the Ghidra project in CodeBrowser.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.tasks.McpTask;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that opens an existing program from the Ghidra project in CodeBrowser.
 * This makes the program visible to other MCP tools that operate on open programs.
 */
public class OpenProgramTool implements McpTool {

    @Override
    public String getName() {
        return "open_program";
    }

    @Override
    public String getDescription() {
        return "Open a program from the Ghidra project in CodeBrowser, or list all " +
               "programs available in the project. " +
               "Use action 'list' to see all project files, or 'open' to open one by name or full path. " +
               "Example: {\"action\": \"open\", \"name\": \"/banks/bank00.bin\"}";
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isIdempotent() {
        return true;
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("action", Map.of(
                    "type", "string",
                    "description", "Operation to perform",
                    "enum", List.of("list", "open")
                )),
                Map.entry("name", Map.of(
                    "type", "string",
                    "description", "Exact program name or full project path to open (required for action 'open')."
                )),
                Map.entry("version", Map.of(
                    "type", "integer", "description", "Optional checked-in version to open read-only; omit for the current version."
                )),
                Map.entry("folder", Map.of(
                    "type", "string",
                    "description", "Project folder to search in (e.g. '/' or '/banks'). Default: search all folders."
                )),
                Map.entry("suppress_analysis_prompt", Map.of(
                    "type", "boolean",
                    "description", "For action 'open': set 'Should Ask To Analyze' to false before opening. Default: true.",
                    "default", true
                )),
                Map.entry("analyze_after_open", Map.of(
                    "type", "boolean",
                    "description", "For action 'open': submit an analyze_program task after opening. Default: false.",
                    "default", false
                )),
                Map.entry("analysis_mode", Map.of(
                    "type", "string",
                    "description", "For analyze_after_open: analysis mode",
                    "enum", List.of("full", "changes"),
                    "default", "full"
                )),
                Map.entry("analysis_options", Map.of(
                    "type", "object",
                    "description", "For analyze_after_open: optional analysis option overrides"
                ))
            ),
            List.of("action"), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return ProjectToolSupport.error("This tool requires backend context (project access).");
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        if (backend != null && backend.isHeadlessSession()) return executeHeadless(arguments, backend);
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        PluginTool pluginTool = manager.getActiveTool();
        if (pluginTool == null) {
            return ProjectToolSupport.error("No active Ghidra tool/window available.");
        }

        Project project = pluginTool.getProject();
        if (project == null) {
            return ProjectToolSupport.error("No Ghidra project is open.");
        }

        String action = (String) arguments.get("action");
        if (action == null || action.isEmpty()) {
            return ProjectToolSupport.error("action parameter is required: 'list' or 'open'");
        }

        DomainFolder rootFolder = project.getProjectData().getRootFolder();

        switch (action.toLowerCase()) {
            case "list":
                return listPrograms(rootFolder, (String) arguments.get("folder"));
            case "open":
                return openProgram(rootFolder, arguments, pluginTool, backend);
            default:
                return ProjectToolSupport.error("Invalid action: " + action + ". Use 'list' or 'open'.");
        }
    }

    private McpSchema.CallToolResult listPrograms(DomainFolder rootFolder, String folderPath) {
        List<DomainFile> files = new ArrayList<>();

        if (folderPath != null && !folderPath.isBlank() && !"/".equals(folderPath)) {
            DomainFolder folder = rootFolder.getFolder(folderPath.replaceFirst("^/", ""));
            if (folder == null) {
                return ProjectToolSupport.error("Folder not found: " + folderPath);
            }
            collectFiles(folder, files);
        } else {
            collectFiles(rootFolder, files);
        }

        if (files.isEmpty()) {
            return textResult("No programs found in the project.");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Programs in project:\n\n");
        for (DomainFile df : files) {
            sb.append("  ").append(df.getPathname());
            sb.append("  (").append(df.getContentType()).append(")\n");
        }
        sb.append("\nTotal: ").append(files.size()).append(" file(s)\n");
        sb.append("\nUse {\"action\": \"open\", \"name\": \"<pathname>\"} to open one in CodeBrowser.");

        return McpSchema.CallToolResult.builder()
            .addTextContent(sb.toString())
            .build();
    }

    private McpSchema.CallToolResult openProgram(DomainFolder rootFolder,
                                                  Map<String, Object> arguments,
                                                  PluginTool pluginTool,
                                                  GhidrAssistMCPBackend backend) {
        String name = (String) arguments.get("name");
        if (name == null || name.isBlank()) {
            return ProjectToolSupport.error("'name' is required for action 'open'.");
        }

        Integer requestedVersion = integerArg(arguments.get("version"));
        if (arguments.containsKey("version") && requestedVersion == null) return ProjectToolSupport.error("version must be an integer");

        // Find the file in the project
        List<DomainFile> allFiles = new ArrayList<>();
        collectFiles(rootFolder, allFiles);

        DomainFile match = findFile(allFiles, name);

        if (match == null) {
            return ProjectToolSupport.error("Program not found: '" + name +
                "'. Use action 'list' to see available programs.");
        }

        // Resolve the exact project file before consulting open instances. An old
        // historical view must never satisfy a request for the current version.
        List<Program> openPrograms = backend.getAllOpenPrograms();
        for (Program p : openPrograms) {
            DomainFile domainFile = p.getDomainFile();
            String pPath = domainFile != null ? domainFile.getPathname() : "";
            int expectedVersion = requestedVersion == null ? match.getVersion() : requestedVersion;
            if (domainFile != null && pPath.equals(match.getPathname()) && domainFileVersion(p) == expectedVersion) {
                if (requestedVersion != null && getBoolean(arguments, "analyze_after_open", false)) return ProjectToolSupport.error("analyze_after_open is not allowed for historical versions");
                StringBuilder sb = new StringBuilder("Program '").append(p.getName()).append("' is already open in CodeBrowser.\n");
                sb.append(maybeSubmitAnalysis(p, arguments, backend));
                return textResult(sb.toString().trim());
            }
        }

        // Open it in CodeBrowser
        ProgramManager pm = pluginTool.getService(ProgramManager.class);
        if (pm == null) {
            return ProjectToolSupport.error("ProgramManager service not available. Is CodeBrowser open?");
        }

        Program program = null;
        boolean acquiredConsumer = false;
        try {
            if (requestedVersion != null) {
                if (getBoolean(arguments, "analyze_after_open", false)) return ProjectToolSupport.error("analyze_after_open is not allowed for historical versions");
                if (requestedVersion < 0 || requestedVersion > match.getLatestVersion()) {
                    return ProjectToolSupport.error("Version " + requestedVersion + " is unavailable; latest is " + match.getLatestVersion());
                }
                program = pm.openProgram(match, requestedVersion, ProgramManager.OPEN_CURRENT);
                if (program == null) return ProjectToolSupport.error("Ghidra could not open historical version " + requestedVersion + " of '" + match.getPathname() + "'.");
            }
            else {
                program = (Program) match.getDomainObject(this, false, false, TaskMonitor.DUMMY);
                acquiredConsumer = true;
                if (getBoolean(arguments, "suppress_analysis_prompt", true)) AnalysisUtils.setAskToAnalyze(program, false);
                pm.openProgram(program);
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Opened '").append(match.getName()).append("' (").append(match.getPathname())
              .append(") in CodeBrowser.\n");
            if (requestedVersion != null) sb.append("Version: ").append(requestedVersion).append(" (read-only historical view)\n");
            sb.append("Language: ").append(program.getLanguageID()).append("\n");
            sb.append("Image Base: ").append(program.getImageBase()).append("\n");
            sb.append("Should Ask To Analyze: ").append(AnalysisUtils.shouldAskToAnalyze(program)).append("\n");
            sb.append(maybeSubmitAnalysis(program, arguments, backend));
            return textResult(sb.toString().trim());
        } catch (Exception e) {
            Msg.error(this, "Failed to open program: " + match.getName(), e);
            return ProjectToolSupport.error("Failed to open '" + match.getName() + "': " + e.getMessage());
        } finally {
            if (program != null && acquiredConsumer) {
                program.release(this);
            }
        }
    }

    private String maybeSubmitAnalysis(Program program, Map<String, Object> arguments,
                                       GhidrAssistMCPBackend backend) {
        if (!getBoolean(arguments, "analyze_after_open", false)) {
            return "";
        }
        if (backend == null || backend.getTaskManager() == null) {
            return "Analysis not submitted: task manager unavailable.\n";
        }

        Map<String, Object> taskArgs = new HashMap<>();
        taskArgs.put("scope", "current");
        Object mode = arguments.get("analysis_mode");
        if (mode != null) {
            taskArgs.put("mode", mode);
        }
        Object options = arguments.get("analysis_options");
        if (options != null) {
            taskArgs.put("options", options);
        }

        AnalyzeProgramTool analyzeTool = new AnalyzeProgramTool();
        McpTask task = backend.submitTask(
            analyzeTool.getName(), taskArgs, program,
            taskContext -> analyzeTool.execute(taskArgs, program, backend, taskContext));

        return "Analysis task submitted: " + task.getTaskId() +
            "\nUse get_task_status with this task_id to retrieve the result.\n";
    }

    private boolean getBoolean(Map<String, Object> arguments, String name, boolean defaultValue) {
        Object value = arguments.get(name);
        if (value instanceof Boolean bool) {
            return bool;
        }
        return defaultValue;
    }

    private McpSchema.CallToolResult executeHeadless(Map<String,Object> arguments, GhidrAssistMCPBackend backend) {
        if (!(backend.getProject() instanceof Project project)) return ProjectToolSupport.error("No headless project is bound.");
        String action = arguments.get("action") instanceof String s ? s.toLowerCase() : "";
        if ("list".equals(action)) return listPrograms(project.getProjectData().getRootFolder(), (String) arguments.get("folder"));
        if (!"open".equals(action)) return ProjectToolSupport.error("Invalid action: " + action + ". Use 'list' or 'open'.");
        String name = arguments.get("name") instanceof String s ? s : null;
        if (name == null || name.isBlank()) return ProjectToolSupport.error("'name' is required for action 'open'.");
        List<DomainFile> files = new ArrayList<>(); collectFiles(project.getProjectData().getRootFolder(), files);
        DomainFile file = findFile(files, name);
        if (file == null) return ProjectToolSupport.error("Program not found or selector is ambiguous: '" + name + "'.");
        Integer version = integerArg(arguments.get("version"));
        if (arguments.containsKey("version") && version == null) return ProjectToolSupport.error("version must be an integer");
        if (version != null && (version < 1 || version > file.getLatestVersion())) return ProjectToolSupport.error("Requested historical version is unavailable");
        if (version != null && getBoolean(arguments, "analyze_after_open", false)) return ProjectToolSupport.error("analyze_after_open is not allowed for historical versions");
        try {
            Program program = backend.openProjectProgram(file, version == null ? DomainFile.DEFAULT_VERSION : version, TaskMonitor.DUMMY);
            return textResult("Opened '" + file.getPathname() + "' in headless mode" + (version == null ? "" : " (historical version " + version + ")") + "\n" + maybeSubmitAnalysis(program, arguments, backend));
        } catch (Exception e) { return ProjectToolSupport.error("Failed to open '" + file.getPathname() + "': " + e.getMessage()); }
    }

    private Integer integerArg(Object value) {
        if (value instanceof Integer n) return n;
        if (value instanceof Long n && n >= Integer.MIN_VALUE && n <= Integer.MAX_VALUE) return n.intValue();
        if (value instanceof String s && s.matches("[0-9]+")) try { return Integer.valueOf(s); } catch (NumberFormatException ignored) { }
        return null;
    }

    private int domainFileVersion(Program program) {
        return program.getDomainFile() == null ? -1 : program.getDomainFile().getVersion();
    }

    /**
     * Find a file by full project path or name, with exact, case-insensitive,
     * then partial matching. Full pathname (e.g. "/banks/bank00.bin") is tried
     * before plain name so that callers can paste directly from the 'list' output.
     */
    private DomainFile findFile(List<DomainFile> files, String name) {
        List<DomainFile> exactPath = files.stream().filter(df -> df.getPathname().equals(name)).toList();
        if (exactPath.size() == 1) return exactPath.get(0);
        if (exactPath.size() > 1) return null;
        List<DomainFile> exactName = files.stream().filter(df -> df.getName().equals(name)).toList();
        if (exactName.size() == 1) return exactName.get(0);
        if (exactName.size() > 1) return null;
        List<DomainFile> insensitive = files.stream().filter(df ->
            df.getPathname().equalsIgnoreCase(name) || df.getName().equalsIgnoreCase(name)).toList();
        return insensitive.size() == 1 ? insensitive.get(0) : null;
    }

    private void collectFiles(DomainFolder folder, List<DomainFile> result) {
        for (DomainFile df : folder.getFiles()) {
            result.add(df);
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectFiles(sub, result);
        }
    }

    private static McpSchema.CallToolResult textResult(String message) {
        return McpSchema.CallToolResult.builder()
            .addTextContent(message)
            .build();
    }
}
