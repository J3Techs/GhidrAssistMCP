package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Map;

import org.junit.jupiter.api.*;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

/** Boundary coverage for the compatibility query tools in WP06. */
class LegacyQueryBoundsTest {
    private final Object consumer = new Object();
    private ProgramDB program;

    @BeforeAll
    static void initialize() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    @BeforeEach
    void fixture() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("legacy-query-fixture", language, language.getDefaultCompilerSpec(), consumer);
        int tx = program.startTransaction("disposable query fixture");
        try {
            var start = program.getAddressFactory().getAddress("1000");
            program.getMemory().createInitializedBlock("text", start, 64, (byte) 0, TaskMonitor.DUMMY, false);
            program.getMemory().createUninitializedBlock("unreadable", start.add(64), 16, false);
            program.getMemory().setBytes(start, new byte[] {(byte) 0x55, (byte) 0x8b, (byte) 0xec, (byte) 0x90, (byte) 0xc3});
            new ghidra.app.cmd.disassemble.DisassembleCommand(start, new AddressSet(start, start.add(4)), true)
                .applyTo(program);
            if (program.getFunctionManager().getFunctionAt(start) == null)
                program.getFunctionManager().createFunction("legacy_fixture", start,
                    new AddressSet(start, start.add(4)), SourceType.USER_DEFINED);
        } finally { program.endTransaction(tx, true); }
    }

    @AfterEach
    void release() { program.release(consumer); }

    @Test
    void allLegacyPageArgumentsRejectFractionsOverflowNegativeAndStrings() {
        Object[] invalid = {-1, 0, 1.5, Long.MAX_VALUE, "2"};
        for (Object value : invalid) {
            assertTrue(new ListDataTool().execute(Map.of("limit", value), program).isError(), "data " + value);
            assertTrue(new ListSegmentsTool().execute(Map.of("limit", value), program).isError(), "segments " + value);
            assertTrue(new ListImportsTool().execute(Map.of("limit", value), program).isError(), "imports " + value);
            assertTrue(new GetBasicBlocksTool().execute(Map.of("function", "1000", "limit", value), program).isError(), "blocks " + value);
            assertTrue(new GetHexdumpTool().execute(Map.of("address", "1000", "len", value), program).isError(), "hexdump " + value);
        }
        assertFalse(new ListSegmentsTool().execute(Map.of("limit", 1), program).isError());
    }

    @Test
    void listPagesExposeContinuationAndNoMoreState() {
        String first = text(new ListSegmentsTool().execute(Map.of("limit", 1), program));
        assertTrue(first.contains("has_more=true"), first);
        assertTrue(first.contains("next_offset=1"), first);
        String end = text(new ListSegmentsTool().execute(Map.of("offset", 99, "limit", 1), program));
        assertTrue(end.contains("has_more=false"), end);

        String imports = text(new ListImportsTool().execute(Map.of("limit", 1), program));
        assertTrue(imports.contains("has_more=false"), imports);
    }

    @Test
    void hexdumpPreservesUnreadableMarkersAndBoundsLargeOutput() {
        String mixed = text(new GetHexdumpTool().execute(Map.of("address", "103f", "len", 3), program));
        assertTrue(mixed.contains("00 ?? ??"), mixed);
        assertTrue(mixed.contains("Unreadable bytes: 2"), mixed);
        String bounded = text(new GetHexdumpTool().execute(Map.of("address", "1000", "len", 65536), program));
        assertTrue(bounded.contains("TRUNCATED"), bounded);
        assertTrue(bounded.length() <= BoundedQueryText.PAGE_CHARS, "length=" + bounded.length());
        assertTrue(bounded.contains("Continue at address"), bounded);
        assertTrue(bounded.contains("repeats any partial line"), bounded);
    }

    @Test
    void basicBlocksHavePageInputsAndBoundedContinuation() {
        var schema = new GetBasicBlocksTool().getInputSchema().toString();
        assertTrue(schema.contains("offset") && schema.contains("limit"), schema);
        String page = text(new GetBasicBlocksTool().execute(Map.of("function", "legacy_fixture", "limit", 1), program));
        assertTrue(page.contains("Page: offset=0, limit=1"), page);
    }

    @Test
    void structuredImportsKeepReferenceBudgetContract() {
        var result = new ListImportsTool().execute(Map.of("structured", true, "limit", 1, "reference_limit", 1), program);
        assertFalse(result.isError(), result.content().toString());
        assertNotNull(result.structuredContent());
        assertTrue(((Map<?, ?>) result.structuredContent()).containsKey("has_more"));
        assertTrue(new ListImportsTool().execute(Map.of("structured", true, "reference_limit", 0), program).isError());
    }

    private static String text(McpSchema.CallToolResult result) {
        assertFalse(Boolean.TRUE.equals(result.isError()), result.content().toString());
        return ((McpSchema.TextContent) result.content().getFirst()).text();
    }
}
