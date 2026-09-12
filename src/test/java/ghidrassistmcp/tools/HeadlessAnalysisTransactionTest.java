package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

import ghidra.GhidraApplicationLayout;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class HeadlessAnalysisTransactionTest {
    private ProgramDB program;

    @BeforeAll static void initialize() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
    }

    @BeforeEach void create() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("headless-analysis-transaction", language, language.getDefaultCompilerSpec(), this);
        int tx = program.startTransaction("fixture");
        try {
            var entry = program.getAddressFactory().getAddress("1000");
            program.getMemory().createInitializedBlock("text", entry, 16, (byte) 0x90, TaskMonitor.DUMMY, false);
            program.getOptions(Program.ANALYSIS_PROPERTIES).registerOption("Fixture.Toggle", true, null, "test flag");
        } finally { program.endTransaction(tx, true); }
    }

    @AfterEach void close() { program.release(this); }

    private AtomicBoolean scheduleWriter(boolean cancel) {
        var wrote = new AtomicBoolean();
        var analyzer = new AbstractAnalyzer("Transaction fixture", "Writes through the native analysis queue", AnalyzerType.BYTE_ANALYZER) {
            @Override public boolean added(Program p, AddressSetView set, TaskMonitor monitor, MessageLog log) {
                // A swallowed native analyzer exception must not make the test pass.
                p.getOptions(Program.PROGRAM_INFO).setString("Fixture.AnalysisWrite", "completed");
                wrote.set(true);
                if (cancel) monitor.cancel();
                return true;
            }
        };
        AnalysisUtils.getManager(program).scheduleOneTimeAnalysis(analyzer, new AddressSet(program.getMemory()));
        return wrote;
    }

    @ParameterizedTest @ValueSource(strings = {"full", "changes"})
    void nativeAnalyzerWritesWithoutCallerTransaction(String mode) {
        var wrote = scheduleWriter(false);
        assertNull(program.getCurrentTransactionInfo());
        var result = new AnalyzeProgramTool().execute(Map.of("mode", mode, "options", Map.of("Fixture.Toggle", false)), program);
        assertFalse(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
        assertTrue(wrote.get(), "Native analyzer must actually perform its database write");
        assertEquals("completed", program.getOptions(Program.PROGRAM_INFO).getString("Fixture.AnalysisWrite", ""));
        assertTrue(program.getOptions(Program.ANALYSIS_PROPERTIES).isDefaultValue("Fixture.Toggle"));
        assertFalse(AnalysisUtils.getManager(program).isAnalyzing());
        assertNull(program.getCurrentTransactionInfo());
    }

    @Test void cancellationClosesTransactionAndRestoresOptionsAfterNativeWorkStops() {
        var wrote = scheduleWriter(true);
        var monitor = new TaskMonitorAdapter(true);
        assertThrows(CancellationException.class, () -> AnalysisUtils.runAnalysis(program, "changes", null,
            Map.of("Fixture.Toggle", false), monitor));
        assertTrue(wrote.get());
        // Match native headless analysis: completed work survives cancellation, but is not saved.
        assertEquals("completed", program.getOptions(Program.PROGRAM_INFO).getString("Fixture.AnalysisWrite", ""));
        assertTrue(program.getOptions(Program.ANALYSIS_PROPERTIES).isDefaultValue("Fixture.Toggle"));
        assertFalse(AnalysisUtils.getManager(program).isAnalyzing());
        assertNull(program.getCurrentTransactionInfo());
    }
}
