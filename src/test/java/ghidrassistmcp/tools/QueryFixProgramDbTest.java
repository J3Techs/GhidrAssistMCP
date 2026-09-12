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
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

class QueryFixProgramDbTest {
    private final Object consumer = new Object();
    private ProgramDB program;
    @BeforeAll static void initialize() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }
    @BeforeEach void fixture() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("query-fixture", language, language.getDefaultCompilerSpec(), consumer);
        int tx = program.startTransaction("disposable fixture");
        try {
            var start = program.getAddressFactory().getAddress("1000");
            program.getMemory().createInitializedBlock("bytes", start, 64, (byte)0, TaskMonitor.DUMMY, false);
            program.getMemory().createUninitializedBlock("unreadable", start.add(64), 16, false);
            for (int i = 0; i < 6; i++) {
                var entry = start.add(i * 8);
                program.getFunctionManager().createFunction("fixture_" + i, entry, new AddressSet(entry, entry.add(7)), SourceType.USER_DEFINED);
                if (i > 0) program.getReferenceManager().addMemoryReference(start.add(i), entry, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            }
        } finally { program.endTransaction(tx, true); }
    }
    @AfterEach void release() { program.release(consumer); }
    @Test void unreadableBytesAreNeverReportedAsZeroAndWrappingIsRejected() {
        String mixed = text(new GetHexdumpTool().execute(Map.of("address", "103f", "len", 3), program));
        assertTrue(mixed.contains("00 ?? ??"), mixed);
        assertTrue(mixed.contains("Unreadable bytes: 2"), mixed);
        assertTrue(new GetHexdumpTool().execute(Map.of("address", "ffffffff", "len", 2), program).isError());
        assertTrue(text(new GetHexdumpTool().execute(Map.of("address", "2000", "len", 1), program)).contains("Unreadable bytes: 1"));
    }
    @Test void listingKeepsPaginationAndGraphCapsRowsAcrossDirections() {
        String page = text(new ListFunctionsTool().execute(Map.of("offset", 1, "limit", 2), program));
        assertFalse(page.contains("fixture_0"), page);
        assertTrue(page.contains("fixture_1") && page.contains("fixture_2"), page);
        assertFalse(page.contains("fixture_3"), page);
        String graph = text(new GetCallGraphTool().execute(Map.of("function", "1001", "max_nodes", 3), program));
        assertTrue(graph.contains("TRUNCATED"), graph);
        assertTrue(graph.lines().filter(s -> s.stripLeading().startsWith("- ")).count() <= 3, graph);
        String xrefs = text(new XrefsTool().execute(Map.of("function", "fixture_0", "include_calls", true, "limit", 2), program));
        assertTrue(xrefs.contains("TRUNCATED"), xrefs);
        assertTrue(xrefs.lines().filter(s -> s.stripLeading().startsWith("- ")).count() <= 2, xrefs);
    }
    @Test void relatedToolsResolveQualifiedNamesAndContainingAddresses() throws Exception {
        int tx = program.startTransaction("namespace fixture");
        try {
            var ns = program.getSymbolTable().createNameSpace(null, "Ns", SourceType.USER_DEFINED);
            program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress("1000")).setParentNamespace(ns);
        } finally { program.endTransaction(tx, true); }
        for (String identifier : java.util.List.of("0x1001", "Ns::fixture_0")) {
            assertTrue(text(new GetFunctionInfoTool().execute(Map.of("function_name", identifier), program)).contains("Ns::fixture_0"));
            assertTrue(text(new GetFunctionSignatureTool().execute(Map.of("function_name_or_address", identifier), program)).contains("fixture_0"));
            assertTrue(text(new GetBasicBlocksTool().execute(Map.of("function", identifier), program)).contains("Ns::fixture_0"));
            assertTrue(text(new XrefsTool().execute(Map.of("function", identifier), program)).contains("Entry Point: 00001000"));
            assertTrue(text(new GetCodeTool(null).execute(Map.of("function", identifier, "format", "disassembly"), program)).contains("Ns::fixture_0"));
        }
    }
    @Test void numericBudgetsRejectFractionsAndOverflow() {
        for (Object invalid : new Object[]{1.5, Long.MAX_VALUE, -1, "2"}) {
            assertTrue(new ListFunctionsTool().execute(Map.of("limit", invalid), program).isError());
            assertTrue(new XrefsTool().execute(Map.of("address", "1000", "limit", invalid), program).isError());
            assertTrue(new GetCallGraphTool().execute(Map.of("function", "1000", "max_nodes", invalid), program).isError());
            assertTrue(new GetHexdumpTool().execute(Map.of("address", "1000", "len", invalid), program).isError());
            assertTrue(new GetCodeTool(null).execute(Map.of("function", "1000", "format", "disassembly", "max_items", invalid), program).isError());
        }
    }
    @Test void codeTextLimitsInstructionsAndComments() throws Exception {
        int tx = program.startTransaction("disassemble fixture");
        try {
            var start = program.getAddressFactory().getAddress("1000");
            for (int i = 0; i < 8; i++) program.getMemory().setByte(start.add(i), (byte)0x90);
            assertTrue(new ghidra.app.cmd.disassemble.DisassembleCommand(start, new AddressSet(start, start.add(7)), true).applyTo(program));
            String limited = text(new GetCodeTool(null).execute(Map.of("function", "1001", "format", "disassembly", "max_items", 2), program));
            assertTrue(limited.contains("TRUNCATED"), limited);
            assertFalse(limited.contains("00001002:"), limited);
            program.getListing().setComment(start, ghidra.program.model.listing.CommentType.EOL, "x".repeat(2000));
            String textLimited = text(new GetCodeTool(null).execute(Map.of("function", "1000", "format", "disassembly", "max_chars", 1024), program));
            assertTrue(textLimited.length() <= 1024);
            assertTrue(textLimited.contains("TRUNCATED"));
        } finally { program.endTransaction(tx, true); }
    }
    private static String text(McpSchema.CallToolResult result) {
        assertFalse(Boolean.TRUE.equals(result.isError()), result.content().toString());
        return ((McpSchema.TextContent)result.content().getFirst()).text();
    }
}
