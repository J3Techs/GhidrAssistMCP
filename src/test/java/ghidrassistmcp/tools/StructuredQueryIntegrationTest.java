package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.*;
import org.junit.jupiter.api.*;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.*;
import ghidrassistmcp.decompiler.DecompilerService;

class StructuredQueryIntegrationTest {
    private final Object consumer = new Object();
    private Program program;
    @BeforeAll static void initialize() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
    }
    @BeforeEach void fixture() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        program = new ProgramDB("structured", language, language.getDefaultCompilerSpec(), consumer);
        int tx = program.startTransaction("fixture");
        try {
            var base = program.getAddressFactory().getAddress("1000");
            program.getMemory().createInitializedBlock("text", base, 64, (byte) 0x90, TaskMonitor.DUMMY, false).setExecute(true);
            program.getMemory().setBytes(base, new byte[]{(byte)0x8b,0x44,0x24,0x04,(byte)0x83,(byte)0xc0,0x07,(byte)0xc3});
            new DisassembleCommand(base, new AddressSet(base, base.add(7)), false).applyTo(program, TaskMonitor.DUMMY);
            program.getFunctionManager().createFunction("add_seven", base, new AddressSet(base, base.add(7)), SourceType.USER_DEFINED);
            program.getReferenceManager().addMemoryReference(base.add(16), base.add(32), RefType.READ, SourceType.USER_DEFINED, 0);
            program.getReferenceManager().addMemoryReference(base.add(17), base.add(32), RefType.WRITE, SourceType.USER_DEFINED, 1);
            program.getReferenceManager().addExternalReference(base.add(20), "fixture.dll", "external_fn", null, SourceType.IMPORTED, 0, RefType.UNCONDITIONAL_CALL);
        } finally { program.endTransaction(tx, true); }
    }
    @AfterEach void release() { program.release(consumer); }

    @Test void structuredDecompilerAndInstructionCapsReturnRealNativeFacts() {
        var tool = new GetCodeTool(new DecompilerService(program -> null));
        var result = tool.execute(Map.of("function", "1000", "format", "decompiler", "structured", true, "include_tokens", true), program);
        assertFalse(result.isError(), () -> result.content().toString());
        Map<?, ?> data = (Map<?, ?>) result.structuredContent();
        assertEquals(true, data.get("decompile_completed"));
        assertFalse(((List<?>) data.get("pcode")).isEmpty());
        assertFalse(((List<?>) data.get("tokens")).isEmpty());
        assertEquals("decompiler_high", data.get("pcode_stage"));
        var instructions = tool.execute(Map.of("function", "1000", "format", "disassembly", "structured", true, "max_items", 1), program);
        Map<?, ?> rows = (Map<?, ?>) instructions.structuredContent();
        assertEquals(1, ((List<?>) rows.get("instructions")).size()); assertEquals(true, rows.get("truncated"));
        assertTrue(tool.execute(Map.of("function", "1000", "format", "pcode", "structured", true, "max_items", 0), program).isError());
    }

    @Test void xrefFiltersApplyBeforeLimitAndRetainOperandAndAddressSpaces() {
        var result = new XrefsBatchTool().execute(Map.of("addresses", List.of("1020"), "reference_kind", "write", "operand_index", 1, "per_address_limit", 1), program);
        assertFalse(result.isError(), () -> result.content().toString());
        Map<?, ?> row = (Map<?, ?>) ((List<?>) ((Map<?, ?>) result.structuredContent()).get("results")).get(0);
        List<?> refs = (List<?>) row.get("xrefs"); assertEquals(1, refs.size());
        Map<?, ?> ref = (Map<?, ?>) refs.get(0); assertEquals(1, ref.get("operand_index"));
        assertEquals("ram", ref.get("from_space")); assertEquals(false, row.get("truncated"));
        var bounded = new XrefsBatchTool().execute(Map.of("addresses", List.of("1020"), "reference_kind", "call", "max_scanned", 1), program);
        assertEquals(true, ((Map<?, ?>) bounded.structuredContent()).get("truncated"));
    }

    @Test void structuredExternalSymbolsHaveLibraryAndInboundReference() {
        var result = new ListImportsTool().execute(Map.of("structured", true, "library", "fixture.dll"), program);
        assertFalse(result.isError(), () -> result.content().toString());
        List<?> rows = (List<?>) ((Map<?, ?>) result.structuredContent()).get("imports"); assertEquals(1, rows.size());
        Map<?, ?> row = (Map<?, ?>) rows.get(0); assertEquals("fixture.dll", row.get("library"));
        assertEquals(1, ((List<?>) row.get("references")).size());
    }

    @Test void explicitMissingTargetNeverExecutesToolOnCurrentProgram() {
        var called = new java.util.concurrent.atomic.AtomicBoolean();
        var backend = new GhidrAssistMCPBackend() {
            @Override public Program getCurrentProgram() { return program; }
            @Override public List<Program> getAllOpenPrograms() { return List.of(program); }
        };
        backend.registerTool(new McpTool() {
            public String getName() { return "target_probe"; }
            public String getDescription() { return "fixture"; }
            public io.modelcontextprotocol.spec.McpSchema.JsonSchema getInputSchema() { return null; }
            public io.modelcontextprotocol.spec.McpSchema.CallToolResult execute(Map<String,Object> a, Program p) {
                called.set(true); return ProjectToolSupport.result(Map.of("name", p.getName()));
            }
        });
        try {
            assertTrue(backend.callTool("target_probe", Map.of("program_name", "missing")).isError()); assertFalse(called.get());
            assertFalse(backend.callTool("target_probe", Map.of("program_id", ProgramIdentity.id(program))).isError()); assertTrue(called.get());
        } finally { backend.getTaskManager().shutdown(); }
    }
}
