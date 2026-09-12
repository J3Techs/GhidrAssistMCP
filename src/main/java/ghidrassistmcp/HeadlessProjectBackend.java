package ghidrassistmcp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Backend binding for analyzeHeadless callers. The caller owns the Project
 * lifecycle; this backend owns only consumers acquired for opened Programs.
 */
public class HeadlessProjectBackend extends GhidrAssistMCPBackend {
    private final Project project;
    private final Object consumer = new Object();
    private final List<Program> programs = new ArrayList<>();
    private final Map<Program, Boolean> owned = new IdentityHashMap<>();
    private final Map<Program, Integer> requestedVersions = new IdentityHashMap<>();
    private volatile Program current;
    private volatile boolean stopping;

    public HeadlessProjectBackend(Project project) {
        super();
        if (project == null) throw new IllegalArgumentException("project is required");
        this.project = project;
        // Cursor/window tools have no meaningful headless state. Core project
        // and program tools remain enabled and operate through this backend.
        setToolEnabled("get_current_address", false);
        setToolEnabled("get_current_function", false);
        setToolEnabled("save_project_session", false);
    }

    @Override public Project getProject() { return project; }
    @Override public boolean isHeadlessSession() { return true; }
    @Override public synchronized Program getCurrentProgram() {
        if (current != null && !current.isClosed()) return current;
        programs.removeIf(Program::isClosed);
        current = programs.isEmpty() ? null : programs.get(programs.size() - 1);
        return current;
    }
    @Override public synchronized List<Program> getAllOpenPrograms() {
        programs.removeIf(Program::isClosed);
        return Collections.unmodifiableList(new ArrayList<>(programs));
    }

    @Override public synchronized Program openProjectProgram(DomainFile file, int version, TaskMonitor monitor) throws Exception {
        if (stopping) throw new IllegalStateException("Headless backend is stopping");
        if (file == null) throw new IllegalArgumentException("file is required");
        if (!Program.class.isAssignableFrom(file.getDomainObjectClass())) throw new IllegalArgumentException("File is not a Program");
        if (!java.util.Objects.equals(file.getProjectLocator(), project.getProjectLocator()))
            throw new IllegalArgumentException("File belongs to another project");
        Program found = programs.stream().filter(p -> !p.isClosed() && sameFile(p.getDomainFile(), file) &&
            java.util.Objects.equals(requestedVersions.get(p), version)).findFirst().orElse(null);
        if (found != null) { current = found; return found; }
        Program opened;
        if (version == DomainFile.DEFAULT_VERSION) opened = (Program) file.getDomainObject(consumer, false, false, monitor);
        else opened = (Program) file.getReadOnlyDomainObject(consumer, version, monitor);
        if (opened == null) throw new IllegalStateException("Unable to open program");
        if (!programs.contains(opened)) { programs.add(opened); owned.put(opened, Boolean.TRUE); onProgramActivated(opened); }
        requestedVersions.put(opened, version); current = opened;
        return opened;
    }

    /** Adopt the script's already-open Program without reopening or replacing unsaved state. */
    public synchronized Program adoptProgram(Program program) {
        if (stopping) throw new IllegalStateException("Headless backend is stopping");
        if (program == null || program.isClosed()) throw new IllegalArgumentException("program is required and must be open");
        if (program.getDomainFile().getParent() != null && !java.util.Objects.equals(program.getDomainFile().getProjectLocator(), project.getProjectLocator()))
            throw new IllegalArgumentException("Program belongs to another project");
        if (!programs.contains(program)) {
            if (!program.addConsumer(consumer)) throw new IllegalStateException("Program closed before adoption");
            programs.add(program); owned.put(program, Boolean.TRUE); onProgramActivated(program);
            requestedVersions.put(program, DomainFile.DEFAULT_VERSION);
        }
        current = program;
        return program;
    }

    @Override public synchronized boolean closeProjectProgram(Program program, boolean discard) {
        if (program == null) return false;
        if (program.getCurrentTransactionInfo() != null) throw new IllegalStateException("Program has an active transaction");
        if (program.isChanged() && !discard) return false;
        if (!programs.remove(program)) return false;
        requestedVersions.remove(program);
        if (owned.remove(program) != null && !program.isClosed()) { onProgramDeactivated(program); program.release(consumer); }
        if (current == program) current = programs.isEmpty() ? null : programs.get(programs.size() - 1);
        return true;
    }

    public void shutdownHeadlessPrograms() {
        synchronized (this) { stopping = true; }
        // Never wait under the backend monitor: workers need current/list/open access.
        shutdownWorkers();
        ghidrassistmcp.vt.VTTool.closeProjectSessions(project);
        synchronized (this) {
            for (Program program : new ArrayList<>(programs)) {
                if (program.isChanged()) ghidra.util.Msg.warn(this, "Releasing unsaved headless program; changes are not saved by MCP shutdown: " + ProgramIdentity.id(program));
                if (owned.remove(program) != null && !program.isClosed()) { onProgramDeactivated(program); program.release(consumer); }
            }
            programs.clear(); requestedVersions.clear(); current = null;
        }
    }

    private boolean sameFile(DomainFile a, DomainFile b) {
        if (a == null || b == null) return false;
        return java.util.Objects.equals(a.getFileID(), b.getFileID()) &&
            java.util.Objects.equals(a.getPathname(), b.getPathname()) &&
            java.util.Objects.equals(String.valueOf(a.getProjectLocator()), String.valueOf(b.getProjectLocator()));
    }

    public void enableAgentLabTools() {
        setToolEnabled("export_program", true);
        setToolEnabled("import_file", false); setToolEnabled("scripts", false); setToolEnabled("run_script", false);
        setToolEnabled("get_current_address", false); setToolEnabled("get_current_function", false);
    }
}
