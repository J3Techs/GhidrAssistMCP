package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpOutputSchemas;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema;

/** Actual bounded read results from a disposable in-memory ProgramDB must satisfy their wire schemas. */
class BatchResultSchemaProgramDbTest {
    private static final Object CONSUMER = new Object();
    private ProgramDB program;

    @BeforeAll static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }

    @BeforeEach void createFixture() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("batch-schema-fixture", language, language.getDefaultCompilerSpec(), CONSUMER);
        int tx = program.startTransaction("disposable test fixture");
        try {
            var start = program.getAddressFactory().getAddress("1000");
            program.getMemory().createInitializedBlock("fixture", start, 16, (byte) 0xff, TaskMonitor.DUMMY, false);
            program.getFunctionManager().createFunction("fixture_one", start, new AddressSet(start, start.add(3)), SourceType.USER_DEFINED);
            program.getFunctionManager().createFunction("fixture_two", start.add(4), new AddressSet(start.add(4), start.add(7)), SourceType.USER_DEFINED);
            program.getListing().createData(start.add(8), ByteDataType.dataType);
            program.getSymbolTable().createLabel(start.add(8), "fixture_data", SourceType.USER_DEFINED);
            program.getReferenceManager().addMemoryReference(start, start.add(8), RefType.READ, SourceType.USER_DEFINED, 0);
        } finally { program.endTransaction(tx, true); }
    }

    @AfterEach void releaseFixture() { program.release(CONSUMER); }

    @Test void contextIncludesTypedRecordsAndPartialErrors() {
        var tool = new QueryAddressContextBatchTool();
        Map<?, ?> complete = valid(tool, Map.of("addresses", List.of("1000", "1008"), "byte_length", 1));
        assertEquals(false, complete.get("partial"));
        Map<?, ?> partial = valid(tool, Map.of("addresses", List.of("100f", "invalid"), "byte_length", 4));
        assertEquals(1, partial.get("errors"));
        assertEquals(true, partial.get("partial"));
        Map<?, ?> shortened = valid(tool, Map.of("addresses", List.of("1008"), "xref_limit", 0, "byte_length", 1));
        assertEquals(true, shortened.get("truncated"));
    }

    @Test void symbolMatchesEmptyResultsAndScanCeilingsConform() {
        var tool = new SearchSymbolsBatchTool();
        Map<?, ?> matched = valid(tool, Map.of("queries", List.of("fixture")));
        assertFalse(((List<?>) ((Map<?, ?>) ((List<?>) matched.get("results")).getFirst()).get("matches")).isEmpty());
        Map<?, ?> empty = valid(tool, Map.of("queries", List.of("never_matches")));
        assertEquals(List.of(), ((Map<?, ?>) ((List<?>) empty.get("results")).getFirst()).get("matches"));
        assertEquals(true, valid(tool, Map.of("queries", List.of("fixture"), "scan_limit", 0)).get("truncated"));
    }

    @Test void memoryRowsConformForUnsigned64ShortReadsAndBadAddresses() {
        var tool = new ReadMemoryBatchTool();
        Map<?, ?> full = valid(tool, Map.of("ranges", List.of(Map.of("address", "1000")), "type", "u64"));
        assertEquals("18446744073709551615", ((Map<?, ?>) ((List<?>) full.get("results")).getFirst()).get("value"));
        Map<?, ?> partial = valid(tool, Map.of("ranges", List.of(Map.of("address", "100f"), Map.of("address", "invalid")), "type", "u64"));
        assertEquals(true, partial.get("truncated"));
        assertEquals(true, partial.get("partial"));
        assertEquals(1, partial.get("errors"));
        assertEquals("short read", ((Map<?, ?>) ((List<?>) partial.get("results")).getFirst()).get("value_error"));
    }

    @Test void dynamicTableFieldsAndEmptyTableConform() {
        var tool = new ReadMemoryTableTool();
        var fields = List.of(Map.of("name", "counter", "offset", 0, "width", 8, "type", "u64"));
        Map<?, ?> full = valid(tool, Map.of("base", "1000", "rows", 1, "stride", 8, "fields", fields));
        assertEquals("18446744073709551615", ((Map<?, ?>) ((List<?>) full.get("rows")).getFirst()).get("counter"));
        Map<?, ?> partial = valid(tool, Map.of("base", "100f", "rows", 1, "stride", 8, "fields", fields));
        assertEquals(true, partial.get("partial"));
        assertEquals(true, partial.get("truncated"));
        assertEquals("short_read", ((Map<?, ?>) ((Map<?, ?>) ((List<?>) partial.get("rows")).getFirst()).get("counter")).get("error"));
        assertEquals(List.of(), valid(tool, Map.of("base", "1000", "rows", 0, "stride", 8, "fields", fields)).get("rows"));
    }

    @Test void xrefsConformWithFlowMetadataEmptyResultsAndPerAddressErrors() {
        var tool = new XrefsBatchTool();
        Map<?, ?> full = valid(tool, Map.of("addresses", List.of("1008")));
        Map<?, ?> reference = (Map<?, ?>) ((List<?>) ((Map<?, ?>) ((List<?>) full.get("results")).getFirst()).get("xrefs")).getFirst();
        assertEquals(true, ((Map<?, ?>) reference.get("flow")).get("read"));
        Map<?, ?> partial = valid(tool, Map.of("addresses", List.of("1008", "invalid"), "per_address_limit", 0));
        assertEquals(true, partial.get("partial"));
        assertEquals(1, partial.get("errors"));
        assertEquals(false, valid(tool, Map.of("addresses", List.of("100f"))).get("partial"));
    }

    @Test void inventoryPagesEmptyResultsEdgesAndInexactTotalsConform() {
        var tool = new FunctionInventoryTool();
        Map<?, ?> first = valid(tool, Map.of("limit", 1, "include_edges", true));
        assertEquals(1L, first.get("next_offset"));
        assertEquals(true, first.get("total_matched_is_exact"));
        assertNull(valid(tool, Map.of("offset", 1, "limit", 1)).get("next_offset"));
        Map<?, ?> capped = valid(tool, Map.of("scan_limit", 1));
        assertEquals(false, capped.get("total_matched_is_exact"));
        assertEquals(true, capped.get("scan_truncated"));
        assertEquals(List.of(), valid(tool, Map.of("pattern", "never_matches")).get("functions"));
        assertNull(valid(tool, Map.of("limit", 0)).get("next_offset"));
    }

    @Test void schemasRejectMissingRequiredFieldsAndWrongNestedTypes() {
        var tool = new ReadMemoryBatchTool();
        Map<?, ?> body = valid(tool, Map.of("ranges", List.of(Map.of("address", "1000")), "length", 1));
        Map<String, Object> broken = new LinkedHashMap<>();
        body.forEach((key, value) -> broken.put((String) key, value));
        broken.remove("count");
        assertFalse(McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), broken).valid());
        broken.put("count", 1);
        Map<String, Object> brokenRow = new LinkedHashMap<>();
        ((Map<?, ?>) ((List<?>) body.get("results")).getFirst()).forEach((key, value) -> brokenRow.put((String) key, value));
        brokenRow.put("read", "not an integer");
        broken.put("results", List.of(brokenRow));
        assertFalse(McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), broken).valid());
    }

    @Test void allExceptionRowsAreToolErrorsWithValidStructuredDetails() {
        for (McpTool tool : List.of(new QueryAddressContextBatchTool(), new ReadMemoryBatchTool(), new XrefsBatchTool())) {
            Map<String, Object> args = tool instanceof ReadMemoryBatchTool
                ? Map.of("ranges", List.of(Map.of("address", "invalid"))) : Map.of("addresses", List.of("invalid"));
            var result = tool.execute(args, program);
            assertTrue(result.isError(), tool.getName());
            assertEquals(true, ((Map<?, ?>) result.structuredContent()).get("partial"));
            assertTrue(McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), result.structuredContent()).valid());
        }
    }

    @Test void actualAsyncSubmissionsAndCompletedInventoryValidateAgainstAdvertisedUnion() throws Exception {
        var backend = new GhidrAssistMCPBackend() {
            @Override public Program getCurrentProgram() { return program; }
        };
        backend.setAsyncReadGraceMillis(0); // Exercise the task branch explicitly, including fast fixture reads.
        try {
            for (McpTool tool : List.of(new FunctionInventoryTool(), new XrefsBatchTool())) {
                var args = tool instanceof XrefsBatchTool ? Map.<String, Object>of("addresses", List.of("1008")) : Map.<String, Object>of("limit", 1);
                var submitted = backend.callTool(tool.getName(), args);
                assertFalse(Boolean.TRUE.equals(submitted.isError()), () -> submitted.content().toString());
                var submissionValidation = McpJsonDefaults.getSchemaValidator().validate(McpOutputSchemas.advertised(tool), submitted.structuredContent());
                assertTrue(submissionValidation.valid(), submissionValidation::errorMessage);
                String id = (String) ((Map<?, ?>) submitted.structuredContent()).get("task_id");
                backend.getTaskManager().waitForTask(id, 10000, null);
                var task = backend.getTaskManager().getTask(id);
                assertTrue(task.isTerminal());
                assertNotNull(task.getResult());
                assertFalse(Boolean.TRUE.equals(task.getResult().isError()), () -> task.getResult().content().toString());
                var completedValidation = McpJsonDefaults.getSchemaValidator().validate(McpOutputSchemas.advertised(tool), task.getResult().structuredContent());
                assertTrue(completedValidation.valid(), completedValidation::errorMessage);
            }
        } finally { backend.getTaskManager().shutdown(); }
    }

    private Map<?, ?> valid(McpTool tool, Map<String, Object> args) {
        McpSchema.CallToolResult result = tool.execute(args, program);
        assertFalse(Boolean.TRUE.equals(result.isError()), () -> tool.getName() + ": " + result.content());
        assertNotNull(result.structuredContent(), tool.getName());
        var validation = McpJsonDefaults.getSchemaValidator().validate(tool.getOutputSchema(), result.structuredContent());
        assertTrue(validation.valid(), () -> tool.getName() + ": " + validation.errorMessage() + "\n" + result.structuredContent());
        return (Map<?, ?>) result.structuredContent();
    }
}
