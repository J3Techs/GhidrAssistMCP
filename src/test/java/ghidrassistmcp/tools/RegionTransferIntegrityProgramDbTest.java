package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.lang.reflect.Method;
import java.util.Map;

import org.junit.jupiter.api.*;

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
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Real disposable ProgramDB coverage for the region transfer mutation path. */
class RegionTransferIntegrityProgramDbTest {
    private static Method transfer;
    private final Object consumer = new Object();

    @BeforeAll static void init() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
            new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
        transfer = BulkRegionTransferTool.class.getDeclaredMethod("transferLabels", Program.class, Program.class,
            Address.class, Address.class, long.class, boolean.class, boolean.class, double.class,
            MatcherContracts.LanguageFacts.class, MatcherContracts.LanguageFacts.class, String.class, TaskMonitor.class);
        transfer.setAccessible(true);
    }

    @Test void dryRunDoesNotChangeAnalystNameAndApplyPreservesByDefault() throws Exception {
        try (Fixture f = new Fixture()) {
            Object preview = f.invoke(true, "default_only", TaskMonitor.DUMMY);
            assertEquals("analyst", f.targetFunction.getName());
            assertEquals(0, field(preview, "matched"));
            Object replacePreview = f.invoke(true, "replace", TaskMonitor.DUMMY);
            assertEquals(1, field(replacePreview, "matched"));
            Object applied = f.invoke(false, "default_only", TaskMonitor.DUMMY);
            assertEquals("analyst", f.targetFunction.getName());
            assertEquals(0, field(applied, "matched"));
            f.invoke(false, "replace", TaskMonitor.DUMMY);
            assertEquals("source_name", f.targetFunction.getName());
        }
    }

    @Test void foreignTransactionIsRejectedWithoutAbortingIt() throws Exception {
        try (Fixture f = new Fixture()) {
            int tx = f.target.startTransaction("foreign analyst edit");
            try {
                f.targetFunction.setComment("foreign edit");
                Object result = f.invoke(false, "replace", TaskMonitor.DUMMY);
                assertNotNull(value(result, "fatalError"));
                assertNotNull(f.target.getCurrentTransactionInfo());
                assertEquals("analyst", f.targetFunction.getName());
                assertEquals("foreign edit", f.targetFunction.getComment());
            } finally { f.target.endTransaction(tx, true); }
        }
    }

    @Test void executeRejectsStaleReviewedTokenAfterTargetRevisionChanges() throws Exception {
        try (Fixture f = new Fixture()) {
            var backend = new ghidrassistmcp.GhidrAssistMCPBackend() {
                @Override public java.util.List<Program> getAllOpenPrograms() { return java.util.List.of(f.source, f.target); }
                @Override public Program getCurrentProgram() { return f.target; }
            };
            var args = new java.util.LinkedHashMap<String, Object>();
            args.put("source_program", ghidrassistmcp.ProgramIdentity.id(f.source));
            args.put("target_program", ghidrassistmcp.ProgramIdentity.id(f.target));
            args.put("start_address", "1000"); args.put("end_address", "1020"); args.put("code_offset", 0);
            args.put("dry_run", true); args.put("name_policy", "replace");
            var preview = new BulkRegionTransferTool().execute(args, null, backend);
            assertFalse(preview.isError(), preview.content().toString());
            String token = String.valueOf(((Map<?, ?>) preview.structuredContent()).get("preview_token"));
            int tx = f.target.startTransaction("revision edit"); f.targetFunction.setComment("changed"); f.target.endTransaction(tx, true);
            args.put("dry_run", false); args.put("preview_token", token);
            var stale = new BulkRegionTransferTool().execute(args, null, backend);
            assertTrue(stale.isError(), stale.content().toString());
            assertEquals("analyst", f.targetFunction.getName());
        }
    }

    @Test void cancelledTransferRollsBackItsOwnTransaction() throws Exception {
        try (Fixture f = new Fixture()) {
            TaskMonitor monitor = new TaskMonitorAdapter(true);
            monitor.cancel();
            Object result = f.invoke(false, "replace", monitor);
            assertNotEquals("source_name", f.targetFunction.getName());
            assertTrue(String.valueOf(value(result, "fatalError")).toLowerCase().contains("cancel"));
        }
    }

    private static Object value(Object result, String name) throws Exception {
        var field = result.getClass().getDeclaredField(name); field.setAccessible(true);
        return field.get(result);
    }
    private static int field(Object result, String name) throws Exception {
        Object value = value(result, name);
        return value instanceof Number n ? n.intValue() : 0;
    }

    private static final class Fixture implements AutoCloseable {
        final ProgramDB source, target; final Function sourceFunction, targetFunction;
        Fixture() throws Exception {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            source = new ProgramDB("region-source", language, language.getDefaultCompilerSpec(), this);
            target = new ProgramDB("region-target", language, language.getDefaultCompilerSpec(), this);
            Address sa = source.getAddressFactory().getAddress("1000"), ta = target.getAddressFactory().getAddress("1000");
            for (ProgramDB p : new ProgramDB[]{source, target}) {
                int tx = p.startTransaction("fixture");
                try { p.getMemory().createInitializedBlock("text", p.getAddressFactory().getAddress("1000"), 64, (byte)0x90, TaskMonitor.DUMMY, false); }
                finally { p.endTransaction(tx, true); }
            }
            int tx = source.startTransaction("function");
            sourceFunction = source.getFunctionManager().createFunction("source_name", sa, new AddressSet(sa, sa.add(31)), SourceType.USER_DEFINED); source.endTransaction(tx, true);
            tx = target.startTransaction("function");
            targetFunction = target.getFunctionManager().createFunction("analyst", ta, new AddressSet(ta, ta.add(31)), SourceType.USER_DEFINED); target.endTransaction(tx, true);
        }
        Object invoke(boolean dryRun, String policy, TaskMonitor monitor) throws Exception {
            var sf = MatcherContracts.fromProgram(source).withRangeContext(MatcherContracts.rangeVleContext(source, source.getAddressFactory().getAddress("1000"), source.getAddressFactory().getAddress("1020")));
            var tf = MatcherContracts.fromProgram(target).withRangeContext(MatcherContracts.rangeVleContext(target, null, null));
            return transfer.invoke(new BulkRegionTransferTool(), source, target, source.getAddressFactory().getAddress("1000"), source.getAddressFactory().getAddress("1020"), 0L, dryRun, false, 0.2, sf, tf, policy, monitor);
        }
        public void close() { source.release(this); target.release(this); }
    }
}
