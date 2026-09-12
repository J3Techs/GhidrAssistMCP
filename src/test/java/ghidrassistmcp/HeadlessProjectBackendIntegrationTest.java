package ghidrassistmcp;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.tools.*;

class HeadlessProjectBackendIntegrationTest {
    @TempDir Path temporary;
    private GhidraProject project;
    private Program first;
    private final Object consumer = new Object();

    @BeforeAll static void init() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
    }
    @BeforeEach void setup() throws Exception {
        project = GhidraProject.createProject(temporary.toString(), "HeadlessFixture", false);
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        first = new ProgramDB("first", lang, lang.getDefaultCompilerSpec(), consumer);
        project.getProjectData().getRootFolder().createFile("first", first, TaskMonitor.DUMMY);
        var second = new ProgramDB("second", lang, lang.getDefaultCompilerSpec(), consumer);
        project.getProjectData().getRootFolder().createFile("second", second, TaskMonitor.DUMMY);
        second.release(consumer);
    }
    @AfterEach void teardown() { if (first != null && !first.isClosed()) first.release(consumer); if (project != null) project.close(); }

    @Test void coreToolsWorkWithoutPluginToolAndPersistSave() throws Exception {
        var backend = new HeadlessProjectBackend(project.getProject());
        try {
            backend.adoptProgram(first);
            var list = new ListProgramsTool().execute(Map.of(), null, backend);
            assertFalse(Boolean.TRUE.equals(list.isError()));
            var opened = new OpenProgramTool().execute(Map.of("action", "open", "name", "/second"), null, backend);
            assertFalse(Boolean.TRUE.equals(opened.isError()), () -> opened.content().toString());
            assertEquals(2, backend.getAllOpenPrograms().size());
            int tx = first.startTransaction("headless persistence");
            first.setExecutablePath("headless-persisted");
            first.endTransaction(tx, true);
            var save = new SaveProgramTool().execute(Map.of("paths", java.util.List.of("/first", "/second")), null, backend);
            assertFalse(Boolean.TRUE.equals(save.isError()), () -> save.content().toString());
            assertTrue(Boolean.TRUE.equals(((Map<?, ?>) save.structuredContent()).get("all_succeeded")));
            var close = new CloseProgramTool().execute(Map.of("name", "/second", "ignore_changes", true), null, backend);
            assertFalse(Boolean.TRUE.equals(close.isError()), () -> close.content().toString());
            assertEquals(1, backend.getAllOpenPrograms().size());
            var closeFirst = new CloseProgramTool().execute(Map.of("name", "/first"), null, backend);
            assertFalse(Boolean.TRUE.equals(closeFirst.isError()), () -> closeFirst.content().toString());
        } finally { backend.shutdownHeadlessPrograms(); }
        first.release(consumer); first = null;
        project.close(); project = null;
        project = GhidraProject.openProject(temporary.toString(), "HeadlessFixture", true);
        var reopened = (Program) project.getProjectData().getFile("/first").getDomainObject(consumer, false, false, TaskMonitor.DUMMY);
        assertEquals("headless-persisted", reopened.getExecutablePath());
        reopened.release(consumer);
    }

    @Test void repeatedOpensRetainOneConsumerAndTaskKeepsItsDatabaseAlive()throws Exception{
        var backend=new HeadlessProjectBackend(project.getProject());
        var started=new java.util.concurrent.CountDownLatch(1);var release=new java.util.concurrent.CountDownLatch(1);
        try{
            backend.adoptProgram(first);int count=first.getConsumerList().size();
            assertSame(first,backend.openProjectProgram(first.getDomainFile(),DomainFile.DEFAULT_VERSION,TaskMonitor.DUMMY));
            assertSame(first,backend.openProjectProgram(project.getProjectData().getFile("/first"),DomainFile.DEFAULT_VERSION,TaskMonitor.DUMMY));
            assertEquals(count,first.getConsumerList().size());
            Program retained=first;var task=backend.submitTask("ownership",Map.of(),first,ignored->{started.countDown();try{release.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}assertFalse(retained.isClosed());return io.modelcontextprotocol.spec.McpSchema.CallToolResult.builder().addTextContent("ok").build();});
            assertTrue(started.await(2,java.util.concurrent.TimeUnit.SECONDS));
            first.release(consumer);assertTrue(backend.closeProjectProgram(first,false));assertFalse(first.isClosed());release.countDown();
            backend.getTaskManager().shutdown();assertTrue(first.isClosed());
        }finally{release.countDown();backend.shutdownHeadlessPrograms();}
    }

    @Test void failedServerBindReleasesAdoptedProgram()throws Exception{
        int original=first.getConsumerList().size();var server=GhidrAssistMCPHeadlessServer.getInstance();
        try(var occupied=new java.net.ServerSocket(0)){
            assertThrows(Exception.class,()->server.start(first,project.getProject(),"localhost",occupied.getLocalPort(),"default"));
            assertFalse(server.isRunning());assertEquals(original,first.getConsumerList().size());
        }finally{server.stop();}
    }
}
