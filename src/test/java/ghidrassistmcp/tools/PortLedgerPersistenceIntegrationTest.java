package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.ProgramIdentity;

/** Public transfer workflow persistence coverage for PORT provenance. */
class PortLedgerPersistenceIntegrationTest {
    @Test void transferLedgerSurvivesSaveCloseReopenAndRejectsChangedTarget(@TempDir Path dir) throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
        var project = GhidraProject.createProject(dir.toString(), "PortPersistence", false);
        Object consumer = this;
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        var source = new ProgramDB("source", lang, lang.getDefaultCompilerSpec(), consumer);
        var target = new ProgramDB("target", lang, lang.getDefaultCompilerSpec(), consumer);
        try {
            var sa = source.getAddressFactory().getAddress("1000");
            var ta = target.getAddressFactory().getAddress("1000");
            int st = source.startTransaction("source"); source.getMemory().createInitializedBlock("text", sa, 16, (byte)0x90, TaskMonitor.DUMMY, false); var sf = source.getFunctionManager().createFunction("source_fn", sa, new AddressSet(sa), SourceType.USER_DEFINED); source.endTransaction(st, true);
            int tt = target.startTransaction("target"); target.getMemory().createInitializedBlock("text", ta, 16, (byte)0x90, TaskMonitor.DUMMY, false); target.getFunctionManager().createFunction("old_fn", ta, new AddressSet(ta), SourceType.DEFAULT); target.endTransaction(tt, true);
            project.getProjectData().getRootFolder().createFile("source", source, TaskMonitor.DUMMY);
            project.getProjectData().getRootFolder().createFile("target", target, TaskMonitor.DUMMY);
            String op = "persist-op";
            Map<String,Object> metadata = Map.of("operation_id", op, "source_program_id", ProgramIdentity.id(source), "source_address", "1000", "source_fingerprint", PortLedger.fingerprint(sf), "method", "fixture");
            var result = new BulkTransferLabelsTool().execute(Map.of("target_program", "target", "preview_annotations", false, "name_policy", "replace", "transfers", List.of(Map.of("target_addr", "1000", "name", "new_fn", "port_metadata", metadata))), target, null);
            assertFalse(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
            int ledgerCount = target.getBookmarkManager().getBookmarks(ta).length;
            var repeated = new BulkTransferLabelsTool().execute(Map.of("target_program", "target", "preview_annotations", false, "name_policy", "replace", "transfers", List.of(Map.of("target_addr", "1000", "name", "new_fn", "port_metadata", metadata))), target, null);
            assertFalse(Boolean.TRUE.equals(repeated.isError()), () -> repeated.content().toString());
            assertEquals(ledgerCount, target.getBookmarkManager().getBookmarks(ta).length);
            String beforeOversized = target.getFunctionManager().getFunctionAt(ta).getName();
            String oversized = "x".repeat(3000);
            var rejected = new BulkTransferLabelsTool().execute(Map.of("target_program", "target", "dry_run", true, "transfers", List.of(Map.of("target_addr", "1000", "name", "should_not_apply", "port_metadata", Map.of("operation_id", op, "source_program_id", "source", "source_address", "1000", "source_fingerprint", oversized, "method", "fixture")))), target, null);
            assertTrue(Boolean.TRUE.equals(rejected.isError()));
            assertEquals(beforeOversized, target.getFunctionManager().getFunctionAt(ta).getName());
            target.save("port ledger", TaskMonitor.DUMMY);
            source.save("source", TaskMonitor.DUMMY);
            target.release(consumer); source.release(consumer); target = null; source = null; project.close(); project = GhidraProject.openProject(dir.toString(), "PortPersistence", true);
            Object reopenConsumer = new Object(); var reopened = (ghidra.program.model.listing.Program) project.getProjectData().getFile("/target").getDomainObject(reopenConsumer, false, false, TaskMonitor.DUMMY);
            assertNotNull(reopened.getBookmarkManager().getBookmark(reopened.getAddressFactory().getAddress("1000"), "NOTE", "PORT"));
            long revision = reopened.getModificationNumber();
            var sourceReopened = (ghidra.program.model.listing.Program) project.getProjectData().getFile("/source").getDomainObject(reopenConsumer, false, false, TaskMonitor.DUMMY);
            var backend = new GhidrAssistMCPBackend() { @Override public java.util.List<ghidra.program.model.listing.Program> getAllOpenPrograms() { return List.of(reopened, sourceReopened); } };
            var verifyArgs = Map.<String,Object>of("action", "verify", "address", "1000", "operation_id", op, "expected_target_revision", Long.toString(revision));
            var substitute = new java.util.HashMap<>(verifyArgs); substitute.put("source_program_id", ProgramIdentity.id(reopened));
            assertTrue(new PortLedgerTool().execute(substitute, reopened, backend).isError());
            int changedSource = sourceReopened.startTransaction("source drift");
            sourceReopened.getMemory().setByte(sourceReopened.getAddressFactory().getAddress("1000"), (byte)0xCC);
            sourceReopened.endTransaction(changedSource, true);
            assertTrue(new PortLedgerTool().execute(verifyArgs, reopened, backend).isError());
            assertEquals("applied_unverified", PortLedger.read(reopened.getFunctionManager().getFunctionAt(reopened.getAddressFactory().getAddress("1000"))).get("verification"));
            changedSource = sourceReopened.startTransaction("restore fixture bytes");
            sourceReopened.getMemory().setByte(sourceReopened.getAddressFactory().getAddress("1000"), (byte)0x90);
            sourceReopened.endTransaction(changedSource, true);
            var verified = new PortLedgerTool().execute(Map.of("action", "verify", "address", "1000", "operation_id", op, "expected_target_revision", revision,
                "source_program_id", ProgramIdentity.id(sourceReopened), "source_address", "1000", "source_fingerprint", PortLedger.fingerprint(sourceReopened.getFunctionManager().getFunctionAt(sourceReopened.getAddressFactory().getAddress("1000")))), reopened, backend);
            assertFalse(Boolean.TRUE.equals(verified.isError()), () -> verified.content().toString());
            backend.shutdownWorkers();
            reopened.save("verified", TaskMonitor.DUMMY); sourceReopened.release(reopenConsumer); reopened.release(reopenConsumer); project.close(); project = GhidraProject.openProject(dir.toString(), "PortPersistence", true);
            Object verifyConsumer = new Object(); var checked = (ghidra.program.model.listing.Program) project.getProjectData().getFile("/target").getDomainObject(verifyConsumer, false, false, TaskMonitor.DUMMY);
            assertEquals("verified", PortLedger.read(checked.getFunctionManager().getFunctionAt(checked.getAddressFactory().getAddress("1000"))).get("verification")); checked.release(verifyConsumer);
        } finally { if (target != null && !target.isClosed()) target.release(consumer); if (source != null && !source.isClosed()) source.release(consumer); project.close(); }
    }
}
