package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;

class BsimMatchOperationsTest {
    private static final Object CONSUMER = new Object();

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    @Test
    void twoRowsApplyInOneTargetTransaction(@TempDir Path temporary) throws Exception {
        Fixture fixture = new Fixture(temporary);
        try {
            Map<String, Object> preview = preview(fixture.context, List.of(
                match("first", "1000", true), match("second", "1010", true)));
            Map<String, Object> applied = apply(fixture.context, (String) preview.get("previewId"), List.of(0, 1));
            assertEquals(2, applied.get("count"));
            assertEquals("first", fixture.program.getFunctionManager().getFunctionAt(fixture.address("1000")).getName());
            assertEquals("second", fixture.program.getFunctionManager().getFunctionAt(fixture.address("1010")).getName());
        } finally { fixture.close(); }
    }

    @Test
    void invalidSecondRowRollsBackFirst(@TempDir Path temporary) throws Exception {
        Fixture fixture = new Fixture(temporary);
        try {
            Map<String, Object> preview = preview(fixture.context, List.of(
                match("first", "1000", true), match("", "1010", true)));
            String original = fixture.program.getFunctionManager().getFunctionAt(fixture.address("1000")).getName();
            Map<String, Object> result = apply(fixture.context, (String) preview.get("previewId"), List.of(0, 1));
            assertEquals("rolled_back", ((Map<?, ?>) ((List<?>) result.get("matches")).get(0)).get("status"));
            assertEquals(original, fixture.program.getFunctionManager().getFunctionAt(fixture.address("1000")).getName());
        } finally { fixture.close(); }
    }

    @Test
    void staleTargetIsRejectedAndUserNameIsPreserved(@TempDir Path temporary) throws Exception {
        Fixture fixture = new Fixture(temporary);
        try {
            var function = fixture.program.getFunctionManager().getFunctionAt(fixture.address("1000"));
            int tx = fixture.program.startTransaction("user name");
            function.setName("user_name", SourceType.USER_DEFINED);
            fixture.program.endTransaction(tx, true);
            Map<String, Object> preview = preview(fixture.context, List.of(match("new_name", "1000", false)));
            tx = fixture.program.startTransaction("stale");
            fixture.program.setExecutablePath("changed");
            fixture.program.endTransaction(tx, true);
            assertThrows(IllegalStateException.class, () -> apply(fixture.context,
                (String) preview.get("previewId"), List.of(0)));
            assertEquals("user_name", function.getName());
        } finally { fixture.close(); }
    }

    @Test
    void staleSourceIsRejected(@TempDir Path temporary) throws Exception {
        Fixture fixture = new Fixture(temporary);
        try {
            Map<String, Object> sourceMatch = new java.util.LinkedHashMap<>(match("copied", "1000", true));
            sourceMatch.put("source_program", "fixture");
            sourceMatch.put("source_address", "1010");
            sourceMatch.put("transfer_signature", true);
            Map<String, Object> preview = preview(fixture.context, List.of(sourceMatch));
            int tx = fixture.program.startTransaction("source stale");
            fixture.program.setExecutablePath("changed-source");
            fixture.program.endTransaction(tx, true);
            assertThrows(IllegalStateException.class, () -> apply(fixture.context,
                (String) preview.get("previewId"), List.of(0)));
        } finally { fixture.close(); }
    }

    private static Map<String, Object> match(String name, String address, boolean overwrite) {
        return Map.of("program", "fixture", "address", address, "name", name, "overwrite", overwrite);
    }
    @Test void signatureTransferUsesNativeTypesAndPreservesComments(@TempDir Path temporary) throws Exception {
        Fixture fixture = new Fixture(temporary);
        try {
            Function source = fixture.program.getFunctionManager().getFunctionAt(fixture.address("1010"));
            Function target = fixture.program.getFunctionManager().getFunctionAt(fixture.address("1000"));
            int tx = fixture.program.startTransaction("source signature");
            source.setReturnType(ghidra.program.model.data.IntegerDataType.dataType, SourceType.USER_DEFINED);
            source.setComment("source documentation"); target.setComment("keep my documentation");
            fixture.program.endTransaction(tx, true);
            var preview = preview(fixture.context, List.of(Map.of("program", "fixture", "address", "1000",
                "source_program", "fixture", "source_address", "1010", "transfer_name", false, "transfer_signature", true)));
            var result = apply(fixture.context, preview.get("previewId").toString(), List.of(0));
            assertEquals("applied", ((Map<?, ?>) ((List<?>) result.get("matches")).get(0)).get("status"), result::toString);
            assertTrue(target.getReturnType().isEquivalent(source.getReturnType()));
            assertEquals("keep my documentation", target.getComment());
        } finally { fixture.close(); }
    }
    private static Map<String, Object> preview(BsimContext context, List<Map<String, Object>> matches) throws Exception {
        return operation("preview_matches").handler().execute(context, Map.of("matches", matches), TaskMonitor.DUMMY);
    }
    private static Map<String, Object> apply(BsimContext context, String id, List<Integer> selected) throws Exception {
        return operation("apply_matches").handler().execute(context,
            Map.of("preview_id", id, "selected", selected, "confirm", true), TaskMonitor.DUMMY);
    }
    private static BsimOperation operation(String name) {
        return BsimMatchOperations.operations().stream().filter(o -> o.name().equals(name)).findFirst().orElseThrow();
    }

    private static final class Fixture {
        final GhidraProject project;
        final Program program;
        final BsimContext context;
        Fixture(Path root) throws Exception {
            project = GhidraProject.createProject(root.toString(), "MatchFixture", false);
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            program = new ProgramDB("fixture", language, language.getDefaultCompilerSpec(), CONSUMER);
            int tx = program.startTransaction("fixture");
            Address base = program.getAddressFactory().getAddress("1000");
            program.getMemory().createInitializedBlock("text", base, 0x40, (byte) 0x90, TaskMonitor.DUMMY, false).setExecute(true);
            program.getFunctionManager().createFunction("FUN_1000", base, new AddressSet(base, base.add(7)), SourceType.DEFAULT);
            Address second = base.add(0x10);
            program.getFunctionManager().createFunction("FUN_1010", second, new AddressSet(second, second.add(7)), SourceType.DEFAULT);
            program.endTransaction(tx, true);
            project.getProjectData().getRootFolder().createFile("fixture", program, TaskMonitor.DUMMY);
            context = new BsimContext(program, null, new BsimConnections(root.resolve("settings")), root, null);
        }
        Address address(String value) { return program.getAddressFactory().getAddress(value); }
        void close() {
            try { context.close(); }
            finally {
                try { if (!program.isClosed()) program.release(CONSUMER); }
                finally { project.close(); }
            }
        }
    }
}
