package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.Map;
import org.junit.jupiter.api.Test;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

class PortLedgerProgramDbTest {
    @Test void ledgerIsBoundedIdempotentAndRevisionChecked() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var p = new ProgramDB("port-ledger", lang, lang.getDefaultCompilerSpec(), this);
        try {
            var a = p.getAddressFactory().getAddress("1000");
            int tx = p.startTransaction("fixture");
            p.getMemory().createInitializedBlock("text", a, 16, (byte)0x90, ghidra.util.task.TaskMonitor.DUMMY, false);
            var f = p.getFunctionManager().createFunction("fixture", a, new AddressSet(a), SourceType.USER_DEFINED);
            PortLedger.appliedUnverified(p, f, "op-1", Map.of("operation_id", "op-1", "source_program_id", "source#1", "source_address", "2000", "source_fingerprint", "a".repeat(64), "method", "fixture"));
            p.endTransaction(tx, true);
            var bm = p.getBookmarkManager().getBookmark(a, "NOTE", "PORT");
            assertNotNull(bm); assertTrue(bm.getComment().contains("applied_unverified"));
            long revision = p.getModificationNumber();
            int verifyTx = p.startTransaction("verify");
            assertTrue(PortLedger.markVerified(p, f, revision, "op-1"));
            p.endTransaction(verifyTx, true);
            assertTrue(p.getBookmarkManager().getBookmark(a, "NOTE", "PORT").getComment().contains("verified"));
            assertFalse(PortLedger.markVerified(p, f, revision - 1, "op-1"));
            assertTrue(bm.getComment().length() < 2000);
        } finally { p.release(this); }
    }

    @Test void exactOperationAndChangedBytesRejectVerification() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var p = new ProgramDB("port-ledger-bytes", lang, lang.getDefaultCompilerSpec(), this);
        try {
            var a = p.getAddressFactory().getAddress("1000"); int tx = p.startTransaction("fixture");
            p.getMemory().createInitializedBlock("text", a, 16, (byte) 0x90, ghidra.util.task.TaskMonitor.DUMMY, false);
            var f = p.getFunctionManager().createFunction("fixture", a, new AddressSet(a), SourceType.USER_DEFINED);
            PortLedger.appliedUnverified(p, f, "op-2", Map.of("operation_id", "op-2", "source_program_id", "s", "source_address", "1", "source_fingerprint", "f".repeat(64), "method", "m"));
            p.endTransaction(tx, true); long rev = p.getModificationNumber();
            assertFalse(PortLedger.markVerified(p, f, rev, "op-2-suffix"));
            tx = p.startTransaction("byte change"); p.getMemory().setByte(a, (byte) 0xCC); p.endTransaction(tx, true);
            assertFalse(PortLedger.markVerified(p, f, rev, "op-2"));
        } finally { p.release(this); }
    }
}
