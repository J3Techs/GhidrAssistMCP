package ghidrassistmcp.tools;

import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidrassistmcp.GhidrAssistMCPManager;
import io.modelcontextprotocol.spec.McpSchema;

final class ProjectToolSupport {
    private static final ObjectMapper JSON = new ObjectMapper();
    private ProjectToolSupport() {}

    static Project activeProject() {
        var tool = GhidrAssistMCPManager.getInstance().getActiveTool();
        return tool == null ? null : tool.getProject();
    }

    /** Validate the project captured at submission time before a mutation runs. */
    static void verifyProject(Map<String, Object> args, Project project) {
        if (project == null) throw new IllegalArgumentException("The submission project is no longer open");
        if (!args.containsKey("__project_identity")) return; // synchronous legacy callers have no snapshot
        Object expected = args.get("__project_identity");
        if (!(expected instanceof String value) || value.isBlank()) {
            throw new IllegalArgumentException("Missing submission project identity");
        }
        String actual = String.valueOf(project.getProjectLocator());
        if (!value.equals(actual)) throw new IllegalArgumentException("The active project changed while the operation was queued");
    }

    static String required(Map<String, Object> args, String key) {
        if (args.get(key) instanceof String value && !value.isBlank()) return value.trim();
        throw new IllegalArgumentException(key + " is required");
    }

    static String path(String value) {
        String path = value.trim().replace('\\', '/');
        if (path.matches("^[A-Za-z]:.*") || path.startsWith("//")) {
            throw new IllegalArgumentException("Use a Ghidra project path, not a host filesystem path");
        }
        if (!path.startsWith("/")) path = "/" + path;
        for (String part : path.split("/")) {
            if (part.equals(".") || part.equals("..")) {
                throw new IllegalArgumentException("Project paths cannot contain . or .. components");
            }
        }
        path = path.replaceAll("/+", "/");
        return path.length() > 1 && path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }

    static DomainFolder folder(DomainFolder root, String value) {
        String normalized = path(value);
        DomainFolder folder = root;
        if (normalized.equals("/")) return root;
        for (String part : normalized.substring(1).split("/")) {
            folder = folder.getFolder(part);
            if (folder == null) return null;
        }
        return folder;
    }

    static DomainFile file(DomainFolder root, String value) {
        String normalized = path(value);
        int slash = normalized.lastIndexOf('/');
        DomainFolder parent = folder(root, slash == 0 ? "/" : normalized.substring(0, slash));
        return parent == null ? null : parent.getFile(normalized.substring(slash + 1));
    }

    static McpSchema.CallToolResult result(Map<String, Object> data) {
        return result(data, false);
    }
    static McpSchema.CallToolResult result(Map<String, Object> data, boolean isError) {
        try {
            return McpSchema.CallToolResult.builder().isError(isError).structuredContent(data)
                .addTextContent(JSON.writeValueAsString(data)).build();
        } catch (Exception e) { return error(e.getMessage()); }
    }

    static McpSchema.CallToolResult error(String message) {
        return McpSchema.CallToolResult.builder().isError(true)
            .addTextContent(message == null ? "Project operation failed" : message).build();
    }
}
