/*
 * Headless-compatible MCP server launcher.
 * Starts the Jetty MCP server without requiring the GUI plugin infrastructure.
 * Used by GhidrAssistMCPHeadlessScript to provide MCP tools in analyzeHeadless mode.
 */
package ghidrassistmcp;

import java.util.Collections;
import java.util.List;

import ghidra.program.model.listing.Program;
import ghidra.framework.model.Project;
import ghidra.util.Msg;

/**
 * Manages a headless MCP server instance that holds a direct program reference
 * instead of relying on GhidrAssistMCPManager's PluginTool-based program discovery.
 */
public class GhidrAssistMCPHeadlessServer {

    private static volatile GhidrAssistMCPHeadlessServer instance;
    private static final Object lock = new Object();

    private GhidrAssistMCPServer server;
    private HeadlessBackend headlessBackend;
    private HeadlessProjectBackend projectBackend;
    private volatile boolean running = false;

    private GhidrAssistMCPHeadlessServer() {
    }

    public static GhidrAssistMCPHeadlessServer getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new GhidrAssistMCPHeadlessServer();
                }
            }
        }
        return instance;
    }

    /**
     * Start the MCP server with a direct program reference.
     *
     * @param program The current program from the headless script
     * @param host    Host to bind (typically "localhost" or "0.0.0.0")
     * @param port    Port to bind (typically 8080)
     */
    public synchronized void start(Program program, String host, int port) throws Exception {
        start(program, host, port, "default");
    }

    /**
     * Start the MCP server with a named security profile. The agent_lab profile is
     * intended only for a disposable, container-isolated analysis environment.
     */
    public synchronized void start(Program program, String host, int port, String toolProfile) throws Exception {
        if (running) {
            Msg.info(this, "Headless MCP server already running, updating program");
            if (headlessBackend != null) {
                headlessBackend.setProgram(program);
            }
            return;
        }

        Msg.info(this, "Starting headless MCP server on " + host + ":" + port);

        if (!"default".equals(toolProfile) && !"agent_lab".equals(toolProfile)) {
            throw new IllegalArgumentException("Unknown headless MCP tool profile: " + toolProfile);
        }

        // Create a backend wrapper that holds the program directly
        headlessBackend = new HeadlessBackend(program);
        if ("agent_lab".equals(toolProfile)) {
            headlessBackend.enableAgentLabTools();
            Msg.info(this, "Enabled sandbox-only agent lab MCP tool profile");
        }

        server = new GhidrAssistMCPServer(host, port, headlessBackend);
        try { server.start(); running = true; }
        catch (Exception e) { rollbackStartup(); throw e; }

        Msg.info(this, "Headless MCP server started successfully with " +
                headlessBackend.getAvailableTools().size() + " tools");
    }

    /** Start against the caller-owned project, without CodeBrowser services. */
    public synchronized void start(Program program, Project project, String host, int port, String toolProfile) throws Exception {
        if (running) {
            if (projectBackend == null || !java.util.Objects.equals(projectBackend.getProject().getProjectLocator(), project.getProjectLocator()))
                throw new IllegalStateException("Running MCP server is bound to a different project/runtime");
            if (program != null) projectBackend.adoptProgram(program);
            return;
        }
        if (project == null) throw new IllegalArgumentException("project is required for headless project access");
        if (!"default".equals(toolProfile) && !"agent_lab".equals(toolProfile)) throw new IllegalArgumentException("Unknown headless MCP tool profile: " + toolProfile);
        projectBackend = new HeadlessProjectBackend(project);
        try {
            if (program != null) projectBackend.adoptProgram(program);
            if ("agent_lab".equals(toolProfile)) projectBackend.enableAgentLabTools();
            server = new GhidrAssistMCPServer(host, port, projectBackend);
            server.start(); running = true;
        }
        catch (Exception e) { rollbackStartup(); throw e; }
    }

    private void rollbackStartup() {
        try { if (server != null) server.stop(); } catch (Exception e) { Msg.warn(this, "Startup rollback: " + e.getMessage()); }
        if (headlessBackend != null) headlessBackend.shutdown();
        if (projectBackend != null) projectBackend.shutdownHeadlessPrograms();
        server = null; headlessBackend = null; projectBackend = null; running = false;
    }

    /**
     * Stop the MCP server.
     */
    public synchronized void stop() {
        if (!running && server == null && headlessBackend == null && projectBackend == null) {
            return;
        }
        try {
            if (server != null) {
                server.stop();
            }
            Msg.info(this, "Headless MCP server stopped");
        } catch (Exception e) {
            Msg.error(this, "Error stopping headless MCP server", e);
        } finally {
            if (headlessBackend != null) {
                headlessBackend.shutdown();
            }
            if (projectBackend != null) projectBackend.shutdownHeadlessPrograms();
        }
        server = null;
        headlessBackend = null;
        projectBackend = null;
        running = false;

        synchronized (lock) {
            instance = null;
        }
    }

    public boolean isRunning() {
        return running;
    }

    /**
     * Update the program reference (e.g., when processing a new binary).
     */
    public void setProgram(Program program) {
        if (headlessBackend != null) {
            headlessBackend.setProgram(program);
        }
        if (projectBackend != null && program != null) try {
            projectBackend.adoptProgram(program);
        } catch (Exception e) { Msg.warn(this, "Unable to bind headless project program: " + e.getMessage()); }
    }

    /**
     * A thin wrapper around GhidrAssistMCPBackend that provides a direct program
     * reference instead of going through GhidrAssistMCPManager.
     */
    private static class HeadlessBackend extends GhidrAssistMCPBackend {

        private volatile Program currentProgram;
        private final Object programConsumer = new Object();

        HeadlessBackend(Program program) {
            super();
            for (String tool : List.of("get_current_address", "get_current_function", "save_project_session",
                    "open_program", "close_program", "project_files", "project_repository")) setToolEnabled(tool, false);
            setProgram(program);
        }

        @Override public boolean isHeadlessSession() { return true; }
        @Override public Project getProject() { return null; }

        synchronized void setProgram(Program program) {
            Program oldProgram = this.currentProgram;
            if (oldProgram == program) return;
            if (program != null && !program.isClosed()) program.addConsumer(programConsumer);
            if (oldProgram != null) {
                onProgramDeactivated(oldProgram);
                releaseProgram(oldProgram);
            }
            this.currentProgram = program;
            if (program != null) {
                onProgramActivated(program);
            }
        }

        @Override
        public Program getCurrentProgram() {
            if (currentProgram != null && currentProgram.isClosed()) {
                Msg.warn(this, "Headless current program is closed; clearing program reference");
                currentProgram = null;
            }
            return currentProgram;
        }

        @Override
        public List<Program> getAllOpenPrograms() {
            Program program = getCurrentProgram();
            if (program != null) {
                return Collections.singletonList(program);
            }
            return Collections.emptyList();
        }

        synchronized void shutdown() {
            getTaskManager().shutdown();
            Program program = currentProgram;
            currentProgram = null;
            if (program != null) {
                onProgramDeactivated(program);
                releaseProgram(program);
            }
        }

        void enableAgentLabTools() {
            setToolEnabled("export_program", true);
            // Importing arbitrary paths can expose process secrets, and scripts can
            // spawn processes. The harness owns artifact import and exposes only
            // argv-safe static CLI tools, so both remain disabled in the lab.
            setToolEnabled("import_file", false);
            setToolEnabled("scripts", false);
            setToolEnabled("run_script", false);

            // The harness starts this server with one analyzed program already
            // bound to the backend. UI cursor and project lifecycle operations
            // require CodeBrowser/FrontEnd services and are misleading in this
            // context; list_binaries and the program analysis tools remain fully
            // available against the bound headless program.
            setToolEnabled("open_program", false);
            setToolEnabled("close_program", false);
            setToolEnabled("project_files", false);
            setToolEnabled("project_repository", false);
            setToolEnabled("get_current_address", false);
            setToolEnabled("get_current_function", false);
        }

        private void releaseProgram(Program program) {
            try {
                if (!program.isClosed() && program.isUsedBy(programConsumer)) {
                    program.release(programConsumer);
                }
            } catch (Exception e) {
                Msg.warn(this, "Failed to release headless program consumer: " + e.getMessage(), e);
            }
        }
    }
}
