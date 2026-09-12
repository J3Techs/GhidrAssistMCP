package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

public class CloseProgramTool implements McpTool {

    @Override
    public String getName() {
        return "close_program";
    }

    @Override
    public String getDescription() {
        return "Close an open program in CodeBrowser. If name is omitted, closes the current program. " +
            "Changed programs require save=true or ignore_changes=true.";
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
                Map.entry("name", Map.of(
                    "type", "string",
                    "description", "Open program name or project path to close. If omitted, closes the current program."
                )),
                Map.entry("save", Map.of(
                    "type", "boolean",
                    "description", "Save the program before closing if it has changes. Default: false.",
                    "default", false
                )),
                Map.entry("ignore_changes", Map.of(
                    "type", "boolean",
                    "description", "Close without saving even if the program has changes. Default: false.",
                    "default", false
                ))
            ),
            List.of(), null, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        return execute(arguments, currentProgram, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram,
                                            GhidrAssistMCPBackend backend) {
        if (backend != null && backend.isHeadlessSession()) {
            Program target = currentProgram != null ? currentProgram : backend.getCurrentProgram();
            String name = stringArg(arguments.get("name"), null);
            if (name != null) {
                try {
                    Program named = ghidrassistmcp.ProgramIdentity.resolve(name, backend.getAllOpenPrograms());
                    if ((arguments.containsKey("program_id") || arguments.containsKey("program_name")) && currentProgram != null && named != currentProgram)
                        return ProjectToolSupport.error("name contradicts the dispatcher-selected program");
                    target = named;
                }
                catch (Exception e) { return ProjectToolSupport.error(e.getMessage()); }
            }
            if (target == null) return ProjectToolSupport.error("No headless program is open.");
            boolean discard = Boolean.TRUE.equals(arguments.get("ignore_changes"));
            if (Boolean.TRUE.equals(arguments.get("save")) && target.isChanged()) {
                McpSchema.CallToolResult saved = new SaveProgramTool().execute(Map.of(), target, backend);
                if (Boolean.TRUE.equals(saved.isError())) return saved;
            }
            try {
                String description = describeProgram(target);
                boolean dirty = target.isChanged();
                if (!backend.closeProjectProgram(target, discard)) return ProjectToolSupport.error("Program was not closed; save changes or pass ignore_changes=true.");
                return ProjectToolSupport.result(Map.of("program", description, "released_mcp_consumer", true,
                    "object_closed", target.isClosed(), "had_unsaved_changes", dirty,
                    "note", "Other consumers, including analyzeHeadless, may retain and later save the same object"));
            } catch (Exception e) { return ProjectToolSupport.error("Failed to close program: " + e.getMessage()); }
        }
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        PluginTool pluginTool = currentProgram != null ? manager.getToolForProgram(currentProgram) : manager.getActiveTool();
        if (pluginTool == null) {
            return ProjectToolSupport.error("No active Ghidra tool/window available.");
        }

        ProgramManager programManager = pluginTool.getService(ProgramManager.class);
        if (programManager == null) {
            return ProjectToolSupport.error("ProgramManager service not available. Is CodeBrowser open?");
        }

        String name = stringArg(arguments.get("name"), null);
        boolean save = Boolean.TRUE.equals(arguments.get("save"));
        boolean ignoreChanges = Boolean.TRUE.equals(arguments.get("ignore_changes"));

        Program target = name == null ? (currentProgram != null ? currentProgram : programManager.getCurrentProgram()) :
            GhidrAssistMCPManager.getInstance().getProgramByName(name);
        if (name != null && currentProgram != null && target != null && target != currentProgram) {
            return ProjectToolSupport.error("Program selector contradicts the dispatcher-selected target: " + name);
        }
        if (target == null) {
            if (name == null) {
                return ProjectToolSupport.error("No current program is open.");
            }
            return ProjectToolSupport.error("Open program not found: " + name);
        }

        PluginTool owner = manager.getToolForProgram(target);
        if (owner == null) return ProjectToolSupport.error("No CodeBrowser window owns the selected program: " + describeProgram(target));
        programManager = owner.getService(ProgramManager.class);
        if (programManager == null) return ProjectToolSupport.error("ProgramManager service unavailable for selected program");

        String label = describeProgram(target);
        boolean changedBefore = target.isChanged();
        if (changedBefore && save) {
            McpSchema.CallToolResult saveResult = new SaveProgramTool().execute(Map.of(), target);
            if (Boolean.TRUE.equals(saveResult.isError())) return saveResult;
        }

        boolean changedAfterSave = target.isChanged();
        if (changedAfterSave && !ignoreChanges) {
            return ProjectToolSupport.error("Refusing to close changed program without saving: " + label +
                "\nPass save=true to save first, or ignore_changes=true to close without saving.");
        }

        boolean closed;
        try {
            closed = programManager.closeProgram(target, ignoreChanges);
        } catch (Exception e) {
            Msg.error(this, "Failed to close program: " + label, e);
            return ProjectToolSupport.error("Failed to close " + label + ": " +
                e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        if (!closed) {
            return ProjectToolSupport.error("Program was not closed: " + label);
        }

        if (backend != null) {
            backend.clearCache();
        }

        return textResult("Closed program: " + label + "\n" +
            "Changed Before Close: " + changedBefore + "\n" +
            "Saved Before Close: " + (changedBefore && save) + "\n" +
            "Ignored Unsaved Changes: " + (changedAfterSave && ignoreChanges) + "\n" +
            "Open Programs Remaining: " + programManager.getAllOpenPrograms().length);
    }

    private Program resolveOpenProgram(Program[] openPrograms, String name) {
        List<Program> exactMatches = new ArrayList<>();
        List<Program> caseInsensitiveMatches = new ArrayList<>();

        for (Program program : openPrograms) {
            String programName = program.getName();
            String path = projectPath(program);
            if (programName.equals(name) || name.equals(path)) {
                exactMatches.add(program);
            }
            else if (programName.equalsIgnoreCase(name) || path.equalsIgnoreCase(name)) {
                caseInsensitiveMatches.add(program);
            }
        }

        if (exactMatches.size() == 1) {
            return exactMatches.get(0);
        }
        if (caseInsensitiveMatches.size() == 1) {
            return caseInsensitiveMatches.get(0);
        }
        return null;
    }

    private String describeProgram(Program program) {
        String path = projectPath(program);
        if (!path.isBlank()) {
            return program.getName() + " (" + path + ")";
        }
        return program.getName();
    }

    private String projectPath(Program program) {
        DomainFile domainFile = program.getDomainFile();
        return domainFile != null ? domainFile.getPathname() : "";
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
