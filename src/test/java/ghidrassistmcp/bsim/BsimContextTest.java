package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.net.URL;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

/** Verifies durable program URLs can be reopened without an active UI project. */
class BsimContextTest {
    private static final Object CONSUMER = new Object();

    @Test void boundProjectWinsOverDifferentGlobalProject(@TempDir Path temporary) throws Exception {
        var original = ghidra.framework.main.AppInfo.getActiveProject();
        var bound = GhidraProject.createProject(temporary.toString(), "BoundProject", false);
        var global = GhidraProject.createProject(temporary.toString(), "GlobalProject", false);
        try {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            var program = new ProgramDB("bound_program", language, language.getDefaultCompilerSpec(), CONSUMER);
            try { bound.getProjectData().getRootFolder().createFile("bound_program", program, TaskMonitor.DUMMY); }
            finally { program.release(CONSUMER); }
            ghidra.framework.main.AppInfo.setActiveProject(global.getProject());
            var backend = new ghidrassistmcp.GhidrAssistMCPBackend() {
                @Override public ghidra.framework.model.Project getProject() { return bound.getProject(); }
                @Override public boolean isHeadlessSession() { return true; }
            };
            try (var context = new BsimContext(null, backend, new BsimConnections(temporary.resolve("settings")), temporary, null)) {
                var handles = context.resolvePrograms(Map.of("project_folder", "/"), TaskMonitor.DUMMY);
                assertEquals(1, handles.size());
                assertEquals("bound_program", handles.get(0).program().getName());
                assertEquals(bound.getProject().getProjectLocator(), handles.get(0).program().getDomainFile().getProjectLocator());
            } finally { backend.getTaskManager().shutdown(); }
        } finally { ghidra.framework.main.AppInfo.setActiveProject(original); global.close(); bound.close(); }
    }

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.install.dir"))),
                new HeadlessGhidraApplicationConfiguration());
        }
    }

    @Test
    void resolvesSavedProgramAfterProjectAndProgramAreClosed(@TempDir Path temporary) throws Exception {
        GhidraProject project = GhidraProject.createProject(temporary.toString(), "ContextFixture", false);
        Program program = null;
        String programUrl;
        try {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            program = new ProgramDB("fixture", language, language.getDefaultCompilerSpec(), CONSUMER);
            int transaction = program.startTransaction("fixture");
            try {
                program.setExecutableMD5("0123456789abcdef0123456789abcdef");
                Address base = program.getAddressFactory().getAddress("1000");
                program.getFunctionManager().createFunction("saved_entry", base,
                    new AddressSet(base), SourceType.USER_DEFINED);
                program.endTransaction(transaction, true);
            }
            catch (Exception e) {
                program.endTransaction(transaction, false);
                throw e;
            }
            project.getProjectData().getRootFolder().createFile("fixture", program, TaskMonitor.DUMMY);
            program.getDomainFile().save(TaskMonitor.DUMMY);
            URL url = program.getDomainFile().getLocalProjectURL(null);
            assertNotNull(url);
            programUrl = url.toString();
        }
        finally {
            if (program != null && !program.isClosed()) program.release(CONSUMER);
            project.close();
        }

        BsimContext context = new BsimContext(null, null,
            new BsimConnections(temporary.resolve("settings")), temporary, null);
        try {
            List<BsimContext.ProgramHandle> handles = context.resolvePrograms(
                Map.of("programs", List.of(programUrl)), TaskMonitor.DUMMY);
            assertEquals(1, handles.size());
            try (BsimContext.ProgramHandle handle = handles.get(0)) {
                Program reopened = handle.program();
                assertEquals("0123456789abcdef0123456789abcdef", reopened.getExecutableMD5());
                assertEquals(1, reopened.getFunctionManager().getFunctionCount());
                assertFalse(reopened.canSave(), "A read-only project view must not save changes");
            }
        }
        finally {
            context.close();
        }
    }
}
