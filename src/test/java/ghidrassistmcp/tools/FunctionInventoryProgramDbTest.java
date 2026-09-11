package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
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

class FunctionInventoryProgramDbTest {
    private static final Object CONSUMER = new Object();

    @BeforeAll static void init() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    private static Program fixture() throws Exception {
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        Program p = new ProgramDB("inventory", lang, lang.getDefaultCompilerSpec(), CONSUMER);
        int tx = p.startTransaction("fixture");
        try {
            Address base = p.getAddressFactory().getAddress("0x1000");
            p.getMemory().createInitializedBlock("text", base, 0x100, (byte) 0x90, TaskMonitor.DUMMY, false);
            p.getFunctionManager().createFunction("Read*table", base, new AddressSet(base, base.add(7)), SourceType.USER_DEFINED);
            Address second = base.add(0x20);
            p.getFunctionManager().createFunction("quoted\"name", second, new AddressSet(second, second.add(7)), SourceType.USER_DEFINED);
            p.endTransaction(tx, true);
            return p;
        } catch (Exception e) { p.endTransaction(tx, false); p.release(CONSUMER); throw e; }
    }

    @Test void wildcardRangeHashAndStructuredEscapingWork() throws Exception {
        Program p = fixture();
        try {
            var result = new FunctionInventoryTool().execute(Map.of(
                "pattern", "Read*", "match_mode", "wildcard", "range_start", "0x1000",
                "range_end", "0x1008", "max_bytes", 4, "limit", 10), p);
            assertFalse(result.isError(), () -> result.content().toString());
            Map<?, ?> body = (Map<?, ?>) result.structuredContent();
            List<?> functions = (List<?>) body.get("functions");
            assertEquals(1, functions.size());
            Map<?, ?> row = (Map<?, ?>) functions.get(0);
            assertEquals("Read*table", row.get("name"));
            assertEquals(8, ((String) row.get("entry_bytes")).length());
            assertEquals(64, ((String) row.get("entry_sha256")).length());
            assertTrue(result.content().toString().contains("Read*table"));
        } finally { p.release(CONSUMER); }
    }

    @Test void paginationAndScanCapReportTruncation() throws Exception {
        Program p = fixture();
        try {
            var result = new FunctionInventoryTool().execute(Map.of("limit", 1, "scan_limit", 1), p);
            assertFalse(result.isError());
            Map<?, ?> body = (Map<?, ?>) result.structuredContent();
            assertEquals(true, body.get("scan_truncated"));
            assertEquals(true, body.get("truncated"));
            assertEquals(1, ((List<?>) body.get("functions")).size());
        } finally { p.release(CONSUMER); }
    }
}
