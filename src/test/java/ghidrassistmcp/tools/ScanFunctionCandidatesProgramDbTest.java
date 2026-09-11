package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.file.Path;
import java.util.Map;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
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

class ScanFunctionCandidatesProgramDbTest {
    @TempDir Path temp;
    private GhidraProject project;
    private Program program;
    private final Object consumer = new Object();

    @BeforeAll static void init() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    @BeforeEach void setUp() throws Exception {
        project = GhidraProject.createProject(temp.toString(), "ScanCandidates", false);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        ProgramDB db = new ProgramDB("fixture", language, language.getDefaultCompilerSpec(), consumer);
        project.getProjectData().getRootFolder().createFile("fixture", db, TaskMonitor.DUMMY);
        program = db;
        int tx = program.startTransaction("fixture");
        try {
            Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            program.getMemory().createInitializedBlock("text", base, 0x100, (byte) 0x90, TaskMonitor.DUMMY, false).setExecute(true);
            program.getMemory().setByte(base.add(0x10), (byte) 0xc3);
            // call 0x1005 (inside the existing function), then call 0x1010 (undefined target).
            program.getMemory().setBytes(base.add(0x20), new byte[] {(byte)0xe8, (byte)0xe0, (byte)0xff, (byte)0xff, (byte)0xff,
                (byte)0xe8, (byte)0xe6, (byte)0xff, (byte)0xff, (byte)0xff});
            program.getListing().createFunction("existing", base, new AddressSet(base, base.add(0x0f)), SourceType.USER_DEFINED);
            new DisassembleCommand(base.add(0x20), new AddressSet(base.add(0x20), base.add(0x29)), false)
                .applyTo(program, TaskMonitor.DUMMY);
            program.endTransaction(tx, true);
        } catch (Exception e) { program.endTransaction(tx, false); throw e; }
    }

    @AfterEach void tearDown() {
        if (program != null && !program.isClosed()) program.release(consumer);
        if (project != null) project.close();
    }

    @Test void previewThenApplyCreatesOnlyMissingTargetAndSkipsContainedTarget() {
        Map<String, Object> previewArgs = Map.of("ranges", "ram:1000-ram:1030", "candidate_kind", "call_targets");
        var preview = new ScanFunctionCandidatesTool().execute(previewArgs, program);
        assertFalse(preview.isError(), () -> preview.content().toString());
        assertNull(program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress("ram:1010")));
        assertNotNull(program.getFunctionManager().getFunctionContaining(program.getAddressFactory().getAddress("ram:1005")));

        var applied = new ScanFunctionCandidatesTool().execute(Map.of(
            "ranges", "ram:1000-ram:1030", "candidate_kind", "call_targets", "mode", "apply"), program);
        assertFalse(applied.isError(), () -> applied.content().toString());
        assertNotNull(program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress("ram:1010")),
            () -> "apply result=" + applied.content() + ", structured=" + applied.structuredContent());
        assertNotNull(program.getFunctionManager().getFunctionContaining(program.getAddressFactory().getAddress("ram:1005")));
    }
}
