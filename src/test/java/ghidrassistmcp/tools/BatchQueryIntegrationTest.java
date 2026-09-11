package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema;

class BatchQueryIntegrationTest {
    @TempDir Path temp;
    private GhidraProject project;
    private Program program;
    private final Object consumer = new Object();

    @BeforeAll static void init() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    @BeforeEach void setUp() throws Exception {
        project = GhidraProject.createProject(temp.toString(), "BatchQuery", false);
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        ProgramDB db = new ProgramDB("fixture", language, language.getDefaultCompilerSpec(), consumer);
        project.getProjectData().getRootFolder().createFile("fixture", db, TaskMonitor.DUMMY);
        program = db;
        int tx = program.startTransaction("fixture data");
        try {
            var memory = program.getMemory();
            Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
            memory.createInitializedBlock("ram", base, 64, (byte) 0, TaskMonitor.DUMMY, false);
            memory.setBytes(base, new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16});
            program.getSymbolTable().createLabel(base, "Alpha_Handler", SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(base.add(4), "Beta_Data", SourceType.USER_DEFINED);
            program.getListing().createFunction("Alpha_Handler", base.add(8), new AddressSet(base.add(8), base.add(11)), SourceType.USER_DEFINED);
            program.getReferenceManager().addMemoryReference(base.add(12), base, RefType.READ, SourceType.USER_DEFINED, 0);
        } finally { program.endTransaction(tx, true); }
    }

    @AfterEach void tearDown() {
        if (program != null && !program.isClosed()) program.release(consumer);
        if (project != null) project.close();
    }

    @Test void memoryRowsPreserveOrderAndContinueAfterShortRead() {
        Map<String,Object> a = new LinkedHashMap<>();
        a.put("ranges", List.of(Map.of("address", "ram:1000", "length", 4), Map.of("address", "ram:103f", "length", 4)));
        var result = new ReadMemoryBatchTool().execute(a, program);
        assertFalse(result.isError(), () -> result.content().toString());
        List<?> rows = (List<?>) ((Map<?, ?>) result.structuredContent()).get("results");
        assertEquals(2, rows.size());
        assertEquals(program.getAddressFactory().getAddress("ram:1000").toString(), ((Map<?, ?>) rows.get(0)).get("address"));
        assertEquals(true, ((Map<?, ?>) rows.get(1)).get("truncated"));
        assertEquals(1, ((Map<?, ?>) rows.get(1)).get("read"));
    }

    @Test void symbolSearchModesFiltersAndOutputCapWork() {
        Map<String,Object> a = new LinkedHashMap<>();
        a.put("queries", List.of("Alpha_*", "beta")); a.put("mode", "glob"); a.put("limit", 1);
        var result = new SearchSymbolsBatchTool().execute(a, program);
        assertFalse(result.isError(), () -> result.content().toString());
        List<?> rows = (List<?>) ((Map<?, ?>) result.structuredContent()).get("results");
        assertEquals(2, rows.size());
        assertEquals(1, ((List<?>) ((Map<?, ?>) rows.get(0)).get("matches")).size());
    }

    @Test void typedTableDecodesValuesAndRejectsOverflowAndDuplicateFields() {
        var tool = new ReadMemoryTableTool();
        var fields = List.of(Map.of("name", "sample", "offset", 0, "width", 2, "type", "i16"));
        var result = tool.execute(Map.of("base", "1000", "rows", 2, "stride", 2,
            "fields", fields, "endian", "little"), program);
        assertFalse(result.isError(), result.content().toString());
        var rows = (List<?>) ((Map<?, ?>) result.structuredContent()).get("rows");
        assertEquals(513L, ((Map<?, ?>) rows.get(0)).get("sample"));
        assertEquals(1027L, ((Map<?, ?>) rows.get(1)).get("sample"));
        assertTrue(tool.execute(Map.of("base", "1000", "rows", 1, "stride", 8,
            "fields", List.of(Map.of("offset", Long.MAX_VALUE, "width", 8))), program).isError());
        assertTrue(tool.execute(Map.of("base", "1000", "rows", 1, "stride", 8,
            "fields", List.of(fields.get(0), fields.get(0))), program).isError());
    }

    @Test void contextAndXrefsEnrichAndRespectPerAddressCap() {
        var ctx = new QueryAddressContextBatchTool().execute(Map.of("addresses", List.of("ram:1000", "ram:100c"), "byte_length", 4, "xref_limit", 1), program);
        assertFalse(ctx.isError(), () -> ctx.content().toString());
        assertEquals(2, ((List<?>) ((Map<?, ?>) ctx.structuredContent()).get("results")).size());
        var xr = new XrefsBatchTool().execute(Map.of("addresses", List.of("ram:1000"), "direction", "to", "per_address_limit", 1), program);
        assertFalse(xr.isError(), () -> xr.content().toString());
        Map<?, ?> row = (Map<?, ?>) ((List<?>) ((Map<?, ?>) xr.structuredContent()).get("results")).get(0);
        assertEquals(1, ((List<?>) row.get("xrefs")).size());
        assertTrue(((Map<?, ?>) ((List<?>) row.get("xrefs")).get(0)).containsKey("from_symbols"));
    }

    @Test void tableReaderRejectsMultiplicationBeyondGlobalByteCap() {
        var result = new ReadMemoryTableTool().execute(Map.of("base", "ram:1000", "rows", 1000, "stride", 65536,
            "fields", List.of(Map.of("offset", 0, "width", 1))), program);
        assertTrue(result.isError());
    }
}
