package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;

class BulkTransferLabelsProgramDbTest {
    private static final Object CONSUMER = new Object();

    @BeforeAll static void init() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }
    @AfterAll static void shutdown() { }

    private static Program program() throws Exception {
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        Program p = new ProgramDB("fixture", lang, lang.getDefaultCompilerSpec(), CONSUMER);
        int tx = p.startTransaction("fixture");
        try {
            Address a = p.getAddressFactory().getAddress("0x1000");
            p.getMemory().createInitializedBlock("text", a, 0x100, (byte)0x90, ghidra.util.task.TaskMonitor.DUMMY, false);
            p.getDataTypeManager().addDataType(ghidra.program.model.data.ShortDataType.dataType,
                ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
            p.getFunctionManager().createFunction("old_name", a, new AddressSet(a), SourceType.USER_DEFINED);
            p.endTransaction(tx, true);
            return p;
        } catch (Exception e) { p.endTransaction(tx, false); p.release(CONSUMER); throw e; }
    }

    @Test void defaultPreviewLeavesFunctionAnnotationsUnchanged() throws Exception {
        Program p = program();
        try {
            Function f = p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress("0x1000"));
            var r = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name", "comment", "evidence", "bookmarks", List.of(Map.of("category", "Test", "comment", "mark"))))), p, null);
            assertFalse(r.isError(), () -> r.content().toString());
            // Legacy name transfer remains backward-compatible; new annotation
            // fields are preview-only by default.
            assertEquals("new_name", f.getName());
            assertNull(f.getComment());
            assertEquals(0, p.getBookmarkManager().getBookmarks(f.getEntryPoint()).length);
        } finally { p.release(CONSUMER); }
    }

    @Test void explicitApplyReplacesAnnotationAndInvalidLaterRowRollsBack() throws Exception {
        Program p = program();
        try {
            Function f = p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress("0x1000"));
            int tx = p.startTransaction("seed"); f.setComment("old"); p.endTransaction(tx, true);
            var r = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "replace",
                "transfers", List.of(
                    Map.of("target_addr", "0x1000", "name", "new_name", "comment", "new"),
                    Map.of("target_addr", "0x9999", "name", "bad", "comment", "must rollback"))), p, null);
            assertTrue(r.isError());
            assertEquals("old_name", f.getName(), "transaction rollback must restore legacy name too");
            assertEquals("old", f.getComment(), "transaction rollback must restore annotation");
        } finally { p.release(CONSUMER); }
    }

    @Test void preservePolicyKeepsExistingCommentWhileApplyingNewName() throws Exception {
        Program p = program();
        try {
            Function f = p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress("0x1000"));
            int tx = p.startTransaction("seed"); f.setComment("existing"); p.endTransaction(tx, true);
            var r = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "preserve",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name", "comment", "incoming"))), p, null);
            assertFalse(r.isError(), () -> r.content().toString());
            assertEquals("new_name", f.getName());
            assertEquals("existing", f.getComment());
        } finally { p.release(CONSUMER); }
    }

    @Test void bookmarkAndDataTypeConflictsHonorPolicy() throws Exception {
        Program p = program();
        try {
            Address a = p.getAddressFactory().getAddress("0x1000");
            int tx = p.startTransaction("seed");
            p.getBookmarkManager().setBookmark(a, ghidra.program.model.listing.BookmarkType.NOTE, "Test", "old");
            p.getListing().createData(a, ghidra.program.model.data.ByteDataType.dataType);
            p.endTransaction(tx, true);
            var preserve = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "preserve",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name",
                    "bookmarks", List.of(Map.of("category", "Test", "comment", "new"))))), p, null);
            assertFalse(preserve.isError());
            assertEquals("old", p.getBookmarkManager().getBookmark(a, ghidra.program.model.listing.BookmarkType.NOTE, "Test").getComment());
            var error = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "error",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name",
                    "data_types", List.of(Map.of("data_type", "short"))))), p, null);
            assertTrue(error.isError());
            assertTrue(error.content().toString().contains("data type conflict"));
        } finally { p.release(CONSUMER); }
    }

    @Test void registerContextConflictIsRejectedAndPreserveLeavesValue() throws Exception {
        Program p = program();
        try {
            assertNotNull(p.getProgramContext().getRegister("EAX"));
            var first = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name",
                    "register_context", List.of(Map.of("register", "EAX", "value", "1", "start", "0x1000", "end", "0x1000"))))), p, null);
            assertFalse(first.isError(), () -> first.content().toString());
            var second = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "error",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name",
                    "register_context", List.of(Map.of("register", "EAX", "value", "2", "start", "0x1000", "end", "0x1000"))))), p, null);
            assertTrue(second.isError());
        } finally { p.release(CONSUMER); }
    }

    @Test void preserveDataTypeDoesNotClearInstructionInsideRequestedSpan() throws Exception {
        Program p = program();
        try {
            Address a = p.getAddressFactory().getAddress("0x1000");
            int tx = p.startTransaction("disassemble");
            p.getMemory().getBlock(a).setExecute(true);
            new ghidra.app.cmd.disassemble.DisassembleCommand(a.add(1), new AddressSet(a.add(1)), false)
                .applyTo(p, ghidra.util.task.TaskMonitor.DUMMY);
            p.endTransaction(tx, true);
            assertNotNull(p.getListing().getInstructionAt(a.add(1)), "fixture must contain an interior instruction");
            var r = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "preserve",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name",
                    "data_types", List.of(Map.of("address", "0x1000", "data_type", "short"))))), p, null);
            assertFalse(r.isError(), () -> r.content().toString());
            assertNotNull(p.getListing().getInstructionAt(a.add(1)), "preserve must not erase interior instructions");
        } finally { p.release(CONSUMER); }
    }

    @Test void sameNameStillAppliesExplicitAnnotation() throws Exception {
        Program p = program();
        try {
            Function f = p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress("0x1000"));
            var r = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name", "comment", "same-name annotation"))), p, null);
            assertFalse(r.isError(), () -> r.content().toString());
            assertEquals("same-name annotation", f.getComment());
        } finally { p.release(CONSUMER); }
    }

    @Test void registerConflictChecksInteriorAndPreserveDoesNotOverwrite() throws Exception {
        Program p = program();
        try {
            var reg = p.getProgramContext().getRegister("EAX");
            assertNotNull(reg);
            Address start = p.getAddressFactory().getAddress("0x1000");
            Address end = p.getAddressFactory().getAddress("0x1003");
            int tx = p.startTransaction("seed context");
            p.getProgramContext().setValue(reg, start.add(1), start.add(2), java.math.BigInteger.valueOf(2));
            p.endTransaction(tx, true);
            var error = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "error",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name", "register_context", List.of(
                    Map.of("register", "EAX", "value", "1", "start", start.toString(), "end", end.toString()))))), p, null);
            assertTrue(error.isError());
            assertEquals(java.math.BigInteger.valueOf(2), p.getProgramContext().getValue(reg, start.add(1), false));
            var preserve = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture", "preview_annotations", false, "conflict_policy", "preserve",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name", "register_context", List.of(
                    Map.of("register", "EAX", "value", "1", "start", start.toString(), "end", end.toString()))))), p, null);
            assertFalse(preserve.isError());
            assertEquals(java.math.BigInteger.valueOf(2), p.getProgramContext().getValue(reg, start.add(1), false));
        } finally { p.release(CONSUMER); }
    }
}
