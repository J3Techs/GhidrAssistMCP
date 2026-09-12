package ghidrassistmcp.resources;

import java.awt.GraphicsEnvironment;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.framework.model.Project;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelatorFactory;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
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
        try { return mapper.writeValueAsString(snapshot()); }
        catch (Exception e) { return "{\"error\":\"Unable to serialize runtime capabilities\"}"; }
    }

    /** Shared tool/resource representation; construction never connects to a remote backend. */
    public Map<String, Object> snapshot() {
        return snapshot(true);
    }
    public Map<String, Object> snapshot(boolean includePrograms) {
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("schema_version", 1);
        out.put("resource", URI);
        GhidrAssistMCPBackend backend = backendSupplier.get();
        boolean headless = backend != null ? backend.isHeadlessSession() : GraphicsEnvironment.isHeadless();
        out.put("gui", !headless);
        out.put("headless", headless);
        out.put("ghidra_version", safeGhidraVersion());
        out.put("build_info", buildInfo());
        Map<String,Boolean> states = backend == null ? Map.of() : backend.getToolEnabledStates();
        out.put("registered_tools", states.size());
        out.put("enabled_tools", states.values().stream().filter(Boolean.TRUE::equals).count());
        out.put("protocol", Map.of("sdk_version", "2.0.1", "latest_supported_revision", "2025-11-25",
            "supported_revisions", List.of("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"),
            "stateless_2026_07_28", false, "tasks_extension", false,
            "application_task_api", List.of("wait_task", "get_task_status", "list_tasks", "cancel_task")));
        out.put("async_enabled", backend != null && backend.isAsyncExecutionEnabled());
        out.put("disabled_tools", states.entrySet().stream().filter(e -> !Boolean.TRUE.equals(e.getValue())).map(Map.Entry::getKey).sorted().toList());
        Program active = backend == null ? null : backend.getCurrentProgram();
        Project project = backend == null ? null : backend.getProject();
        out.put("active_project", project == null ? null : String.valueOf(project.getProjectLocator()));
        out.put("headless_session", backend != null && backend.isHeadlessSession());
        out.put("program_manager_available", backend != null && backend.hasProgramManager());
        var programs = backend == null ? List.<Program>of() : ghidrassistmcp.tools.ProgramDiscoverySupport.unique(backend.getAllOpenPrograms());
        out.put("include_programs", includePrograms); out.put("program_count", programs.size());
        out.put("active_program_id", active == null ? null : ProgramIdentity.id(active));
        var counts = new java.util.HashMap<String,Integer>(); for (Program p : programs) counts.merge(ProgramIdentity.id(p),1,Integer::sum);
        out.put("program_id_collisions", counts.entrySet().stream().filter(e->e.getValue()>1).map(e->e.getKey()).sorted().toList());
        if (includePrograms) { out.put("open_programs", programs.stream().map(ProgramIdentity::describe).toList()); out.put("active_program", active == null ? null : ProgramIdentity.describe(active)); }
        out.put("native_version_tracking", Map.of("available", classPresent("ghidra.feature.vt.api.main.VTSession"), "correlators", correlatorNames()));
        out.put("bsim", Map.of("api_available", classPresent("ghidra.features.bsim.query.BSimServerInfo"), "backend_validation", "not verified by this read-only resource"));
        out.put("tasks", Map.of("generic", Map.of("durable", false, "restart_recovery", "generic task records are lost on JVM restart; inspect saved databases before retrying"), "bsim", Map.of("durable_journal", true, "backend_health", "not probed")));
        out.put("unavailable_reasons", List.of("Repository, BSim server, credentials, and remote database health are intentionally not probed; GUI cursor/FrontEnd services are unavailable in headless mode."));
        return out;
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
            for (String key : List.of("revision", "dirty", "built_at", "source_sha256")) if (props.containsKey(key)) info.put(key, props.getProperty(key));
        } catch (Exception e) { info.put("available", false); info.put("error", "build info unavailable"); }
        return info;
    }
}
