package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.Map;
import java.util.concurrent.CancellationException;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import org.junit.jupiter.api.*;

class TemporaryAnalysisOptionsTest {
    private ProgramDB program;
    @BeforeAll static void initialize() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
    }
    @BeforeEach void create() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("temporary-options", language, language.getDefaultCompilerSpec(), this);
        int tx = program.startTransaction("fixture options");
        try {
            var options = program.getOptions(Program.ANALYSIS_PROPERTIES);
            options.registerOption("Fixture.Toggle", true, null, "test flag");
            options.registerOption("Fixture.Number", 10, null, "test count");
            options.setInt("Fixture.Number", 13);
        } finally { program.endTransaction(tx, true); }
    }
    @AfterEach void close() { program.release(this); }

    @Test void typedValuesAndDefaultStateRestoreAfterSuccessFailureAndCancellation() {
        var options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        for (String outcome : java.util.List.of("success", "failure", "cancel")) {
            Runnable operation = () -> AnalysisUtils.withTemporaryOptions(program,
                Map.of("Fixture.Toggle", false, "Fixture.Number", 42), () -> {
                    assertFalse(options.getBoolean("Fixture.Toggle", true));
                    assertEquals(42, options.getInt("Fixture.Number", 0));
                    if (outcome.equals("failure")) throw new IllegalStateException("fixture failure");
                    if (outcome.equals("cancel")) throw new CancellationException("fixture cancellation");
                    return "done";
                });
            if (outcome.equals("success")) operation.run(); else assertThrows(RuntimeException.class, operation::run);
            assertTrue(options.getBoolean("Fixture.Toggle", false));
            assertTrue(options.isDefaultValue("Fixture.Toggle"));
            assertEquals(13, options.getInt("Fixture.Number", 0));
            assertFalse(options.isDefaultValue("Fixture.Number"));
        }
    }
    @Test void invalidModeRangeOrOptionCannotPersistOverrides() {
        var address = program.getAddressFactory().getAddress("1000");
        assertThrows(IllegalArgumentException.class, () -> AnalysisUtils.runAnalysis(program, "invalid", null,
            Map.of("Fixture.Toggle", false), TaskMonitor.DUMMY));
        assertThrows(IllegalArgumentException.class, () -> AnalysisUtils.runAnalysis(program, "changes", new AddressSet(address),
            Map.of("Fixture.Toggle", false), TaskMonitor.DUMMY));
        assertThrows(IllegalArgumentException.class, () -> AnalysisUtils.withTemporaryOptions(program,
            Map.of("Fixture.Toggle", false, "Missing.Option", true), () -> { fail("Must not execute"); return null; }));
        assertTrue(program.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean("Fixture.Toggle", false));
        assertTrue(new AnalyzeProgramTool().execute(Map.of("mode", "changes", "start_address", "1000", "end_address", "1001",
            "options", Map.of("Fixture.Toggle", false)), program).isError());
    }
    @Test void cancelledBatchNeverStartsLaterProgramsOrAppliesTheirOptions() {
        var backend = new ghidrassistmcp.GhidrAssistMCPBackend() {
            @Override public java.util.List<Program> getAllOpenPrograms() { return java.util.List.of(program, program); }
        };
        try {
            var task = new ghidrassistmcp.tasks.McpTask("analyze_program", Map.of());
            task.markStarted(); task.requestCancellation();
            long revision = program.getModificationNumber();
            var result = new AnalyzeProgramTool().execute(Map.of("scope", "all_open", "options", Map.of("Fixture.Toggle", false)), program, backend, task);
            assertTrue(result.isError());
            assertTrue(((io.modelcontextprotocol.spec.McpSchema.TextContent) result.content().getFirst()).text().contains("remaining programs were not started"));
            assertEquals(revision, program.getModificationNumber());
            var monitor = new ghidra.util.task.TaskMonitorAdapter(true); monitor.cancel();
            assertThrows(CancellationException.class, () -> AnalysisUtils.runAnalysis(program, "full", null, Map.of("Fixture.Toggle", false), monitor));
            assertEquals(revision, program.getModificationNumber());
        } finally { backend.getTaskManager().shutdown(); }
    }
}
