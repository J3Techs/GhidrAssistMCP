package ghidrassistmcp.resources;

import java.awt.GraphicsEnvironment;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.GhidrAssistMCPManager;
import ghidrassistmcp.ProgramIdentity;

/** Read-only runtime prerequisites and capability report; performs no remote probes. */
public final class RuntimeCapabilitiesResource implements McpResource {
    private static final String URI = "ghidra://runtime/capabilities";
    private final Supplier<GhidrAssistMCPBackend> backendSupplier;
    private final ObjectMapper mapper = new ObjectMapper();

    public RuntimeCapabilitiesResource() { this(() -> null); }
    public RuntimeCapabilitiesResource(Supplier<GhidrAssistMCPBackend> backendSupplier) { this.backendSupplier = backendSupplier; }
    @Override public String getUriPattern() { return URI; }
    @Override public String getName() { return "runtime_capabilities"; }
    @Override public String getDescription() { return "Installed GhidrAssistMCP runtime, project, native-service and task capability diagnostics"; }
    @Override public String getMimeType() { return "application/json"; }
    @Override public boolean canHandle(String uri) { return URI.equals(uri); }
    @Override public Map<String,String> extractParams(String uri) { return Map.of(); }

    @Override public String readContent(Program ignored, Map<String,String> params) {
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("resource", URI);
        GhidrAssistMCPBackend backend = backendSupplier.get();
        boolean headless = backend != null ? backend.isHeadlessSession() : GraphicsEnvironment.isHeadless();
        out.put("gui", !headless);
        out.put("headless", headless);
        out.put("ghidra_version", safeGhidraVersion());
        out.put("build_info", buildInfo());
        GhidrAssistMCPManager manager = GhidrAssistMCPManager.getInstance();
        Map<String,Boolean> states = backend == null ? Map.of() : backend.getToolEnabledStates();
        out.put("registered_tools", states.size());
        out.put("disabled_tools", states.entrySet().stream().filter(e -> !Boolean.TRUE.equals(e.getValue())).map(Map.Entry::getKey).sorted().toList());
        Program active = backend == null ? null : backend.getCurrentProgram();
        Project project = backend == null ? null : backend.getProject();
        out.put("active_project", project == null ? null : String.valueOf(project.getProjectLocator()));
        out.put("headless_session", backend != null && backend.isHeadlessSession());
        out.put("program_manager_available", backend != null && !backend.isHeadlessSession() && manager.getActiveTool() != null && manager.getActiveTool().getService(ProgramManager.class) != null);
        out.put("open_programs", backend == null ? List.of() : backend.getAllOpenPrograms().stream().map(ProgramIdentity::describe).toList());
        out.put("active_program", active == null ? null : ProgramIdentity.describe(active));
        out.put("native_version_tracking", Map.of("available", classPresent("ghidra.feature.vt.api.main.VTSession"), "correlators", correlatorNames()));
        out.put("bsim", Map.of("api_available", classPresent("ghidra.features.bsim.query.BSimServerInfo"), "backend_validation", "not verified by this read-only resource"));
        out.put("tasks", Map.of("generic", Map.of("durable", false, "restart_recovery", "generic task records are lost on JVM restart; inspect saved databases before retrying"), "bsim", Map.of("durable_journal", true, "backend_health", "not probed")));
        out.put("unavailable_reasons", List.of("Repository, BSim server, credentials, and remote database health are intentionally not probed; GUI cursor/FrontEnd services are unavailable in headless mode."));
        try { return mapper.writeValueAsString(out); } catch (Exception e) { return "{\"error\":\"Unable to serialize runtime capabilities\"}"; }
    }

    private boolean classPresent(String name) { try { Class.forName(name, false, getClass().getClassLoader()); return true; } catch (Throwable e) { return false; } }
    private List<String> correlatorNames() {
        try { return ClassSearcher.getInstances(VTAbstractProgramCorrelatorFactory.class).stream().map(VTAbstractProgramCorrelatorFactory::getName).sorted().toList(); }
        catch (Throwable e) { return List.of(); }
    }
    private String safeGhidraVersion() { try { return ghidra.framework.Application.getApplicationVersion(); } catch (Throwable e) { return "unavailable"; } }
    private Map<String,Object> buildInfo() {
        Map<String,Object> info = new LinkedHashMap<>();
        try (InputStream in = getClass().getClassLoader().getResourceAsStream("build-info.properties")) {
            if (in == null) { info.put("available", false); return info; }
            var props = new java.util.Properties(); props.load(in); info.put("available", true);
            for (String key : List.of("revision", "dirty", "built_at")) if (props.containsKey(key)) info.put(key, props.getProperty(key));
        } catch (Exception e) { info.put("available", false); info.put("error", "build info unavailable"); }
        return info;
    }
}
