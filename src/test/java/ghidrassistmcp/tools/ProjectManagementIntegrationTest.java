package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
import io.modelcontextprotocol.spec.McpSchema;

class ProjectManagementIntegrationTest {
    @TempDir Path temporary;
    private GhidraProject project;
    private Program program;
    private final Object consumer = new Object();

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) {
            Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
        }
    }

    @BeforeEach
    void createDisposableProject() throws Exception {
        assertFalse(temporary.resolve("McpSaveFixture.rep").toFile().exists());
        project = GhidraProject.createProject(temporary.toString(), "McpSaveFixture", false);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("fixture", language, language.getDefaultCompilerSpec(), consumer);
        project.getProjectData().getRootFolder().createFile("fixture", program, TaskMonitor.DUMMY);
    }

    @AfterEach
    void closeDisposableProject() {
        if (program != null && !program.isClosed()) program.release(consumer);
        if (project != null) project.close();
    }

    @Test
    void savePersistsAcrossClosingAndReopeningProject() throws Exception {
        int transaction = program.startTransaction("Test change");
        program.setExecutablePath("mcp-persistence-proof");
        program.endTransaction(transaction, true);
        assertTrue(program.isChanged());
        SaveProgramTool tool = new SaveProgramTool(() -> project.getProject());
        McpSchema.CallToolResult saved = tool.execute(Map.of(), program);
        assertFalse(Boolean.TRUE.equals(saved.isError()), () -> saved.content().toString());
        assertEquals(true, ((Map<?, ?>) saved.structuredContent()).get("saved"));
        assertFalse(program.isChanged());
        assertFalse(program.isClosed(), "Saving must not close the program");
        program.release(consumer);
        program = null;
        project.close();
        project = null;
        project = GhidraProject.openProject(temporary.toString(), "McpSaveFixture", true);
        DomainFile file = project.getProjectData().getFile("/fixture");
        program = (Program) file.getDomainObject(consumer, false, false, TaskMonitor.DUMMY);
        assertEquals("mcp-persistence-proof", program.getExecutablePath());
    }

    @Test
    void saveRefusesActiveTransactionAndDoesNotCommitIt() {
        int transaction = program.startTransaction("Still active");
        try {
            program.setExecutablePath("not-committed");
            var result = new SaveProgramTool(() -> project.getProject()).execute(Map.of(), program);
            assertTrue(result.isError());
            assertNotNull(program.getCurrentTransactionInfo());
        } finally { program.endTransaction(transaction, false); }
    }

    @Test
    void saveCleanProgramReportsNoChanges() {
        var result = new SaveProgramTool(() -> project.getProject()).execute(Map.of("path", "/fixture"), null);
        assertFalse(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
        assertEquals(true, ((Map<?, ?>) result.structuredContent()).get("no_changes"));
    }

    @Test
    void registerReadbackIncludesInteriorValuesAndRefusesIncompleteMutation() {
        var context = program.getProgramContext();
        var register = context.getRegister("EAX");
        assertNotNull(register);
        var start = program.getAddressFactory().getAddress("1000");
        int tx = program.startTransaction("Context fixture");
        try {
            context.setValue(register, start, start.add(3), java.math.BigInteger.ONE);
            context.setValue(register, start.add(1), start.add(2), java.math.BigInteger.TWO);
        } catch (Exception e) { fail(e); }
        finally { program.endTransaction(tx, true); }
        var read = new GetRegisterContextTool().execute(Map.of("register", "EAX", "ranges", "1000-1004"), program);
        assertSuccess(read);
        var rows = (java.util.List<?>) ((Map<?, ?>) read.structuredContent()).get("ranges");
        var segments = (java.util.List<?>) ((Map<?, ?>) rows.get(0)).get("segments");
        assertEquals(3, segments.size());
        assertEquals("0x2", ((Map<?, ?>) segments.get(1)).get("value"));
        assertTrue(new GetRegisterContextTool().execute(Map.of("register", "EAX", "ranges", "1000-1004",
            "max_segments", 2), program).isError());
        assertThrows(IllegalArgumentException.class, () -> SetRegisterContextTool.valueSegments(context,
            register, new SetRegisterContextTool.AddressRange(start, start.add(4)), 2));
        assertEquals(java.math.BigInteger.TWO, context.getValue(register, start.add(1), false));
    }

    @Test
    void fileOperationsPreviewCopyMoveRenameAndRejectCollision() throws Exception {
        ProjectFilesTool tool = new ProjectFilesTool(() -> project.getProject());
        var root = project.getProjectData().getRootFolder();
        assertSuccess(tool.execute(Map.of("action", "create_folder", "path", "/source", "dry_run", true), null, null));
        assertNull(root.getFolder("source"));
        assertSuccess(tool.execute(Map.of("action", "create_folder", "path", "/source"), null, null));
        assertSuccess(tool.execute(Map.of("action", "create_folder", "path", "/dest"), null, null));
        assertTrue(tool.execute(Map.of("action", "create_folder", "path", "/dest"), null, null).isError());
        program.release(consumer);
        program = null;
        assertSuccess(tool.execute(Map.of("action", "copy", "path", "/fixture", "destination_folder", "/source"), null, null));
        assertNotNull(root.getFile("fixture"));
        assertNotNull(root.getFolder("source").getFile("fixture"));
        assertSuccess(tool.execute(Map.of("action", "rename", "path", "/source/fixture", "name", "renamed"), null, null));
        assertSuccess(tool.execute(Map.of("action", "move", "path", "/source/renamed", "destination_folder", "/dest"), null, null));
        assertNull(root.getFolder("source").getFile("renamed"));
        assertNotNull(root.getFolder("dest").getFile("renamed"));
        assertTrue(tool.execute(Map.of("action", "move", "path", "/source", "destination_folder", "/source"), null, null).isError());
        assertTrue(tool.execute(Map.of("action", "create_folder", "path", "C:/host/path"), null, null).isError());
    }

    @Test
    void repositoryStatusAndCheckoutPreconditionForUnversionedFile() {
        var tool = new ProjectRepositoryTool(() -> project.getProject());
        var status = tool.execute(Map.of("action", "status", "path", "/fixture"), program);
        assertSuccess(status);
        assertEquals(false, ((Map<?, ?>) status.structuredContent()).get("versioned"));
        assertTrue(tool.execute(Map.of("action", "checkout", "path", "/fixture"), program).isError());
    }

    private static void assertSuccess(McpSchema.CallToolResult result) {
        assertFalse(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
    }
}
