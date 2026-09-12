package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.ProgramIdentity;
import io.modelcontextprotocol.spec.McpSchema;

/** Native disposable databases: assertions inspect persisted model state, not response wording alone. */
class MutationCorrectnessProgramDbTest {
    private final Object consumer = new Object();
    private ProgramDB program;
    @TempDir Path temp;
    @BeforeAll static void initialize() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }
    @BeforeEach void fixture() throws Exception { program = makeProgram(); }
    ProgramDB makeProgram() throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        ProgramDB p = new ProgramDB("mutation-fixture", language, language.getDefaultCompilerSpec(), consumer);
        int tx = p.startTransaction("disposable fixture");
        try {
            p.getMemory().createInitializedBlock("text", p.getAddressFactory().getAddress("1000"), 0x100,
                (byte)0xc3, TaskMonitor.DUMMY, false).setExecute(true);
            p.getDataTypeManager().addDataType(IntegerDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
            p.getDataTypeManager().addDataType(FloatDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
        } finally { p.endTransaction(tx, true); }
        return p;
    }
    @AfterEach void release() { program.release(consumer); }
    Address at(String hex) { return program.getAddressFactory().getAddress(hex); }
    void mixedUnits() throws Exception {
        int tx = program.startTransaction("mixed fixture");
        try {
            assertTrue(new ghidra.app.cmd.disassemble.DisassembleCommand(at("1000"), new AddressSet(at("1000")), false).applyTo(program));
            program.getListing().createData(at("1008"), DWordDataType.dataType);
            program.getFunctionManager().createFunction("fixture", at("1000"), new AddressSet(at("1000")), SourceType.USER_DEFINED);
        } finally { program.endTransaction(tx, true); }
    }
    @Test void selectiveClearPreservesUnselectedKindsForEveryFlagCombination() throws Exception {
        for (boolean instructions : new boolean[] {false, true}) for (boolean data : new boolean[] {false, true}) {
            mixedUnits();
            var args = new HashMap<String,Object>(Map.of("ranges", "1000-1010", "clear_functions", false,
                "clear_instructions", instructions, "clear_data", data, "dry_run", true));
            ok(new ClearCodeRangesTool().execute(args, program));
            assertNotNull(program.getListing().getInstructionAt(at("1000")));
            assertNotNull(program.getListing().getDefinedDataAt(at("1008")));
            args.put("dry_run", false);
            ok(new ClearCodeRangesTool().execute(args, program));
            assertEquals(!instructions, program.getListing().getInstructionAt(at("1000")) != null);
            assertEquals(!data, program.getListing().getDefinedDataAt(at("1008")) != null);
            assertNotNull(program.getFunctionManager().getFunctionAt(at("1000")));
            int tx = program.startTransaction("reset fixture");
            try { program.getFunctionManager().removeFunction(at("1000")); program.getListing().clearCodeUnits(at("1000"), at("100f"), false); }
            finally { program.endTransaction(tx, true); }
        }
    }
    @Test void partialCodeUnitsRejectBeforeAnyClearingAndOverlapsCountOnce() throws Exception {
        mixedUnits();
        for (String range : List.of("1000-100a", "1009-1010")) {
            assertTrue(new ClearCodeRangesTool().execute(Map.of("ranges", range), program).isError());
            assertNotNull(program.getListing().getInstructionAt(at("1000")));
            assertNotNull(program.getListing().getDefinedDataAt(at("1008")));
            assertNotNull(program.getFunctionManager().getFunctionAt(at("1000")));
        }
        var preview = new ClearCodeRangesTool().execute(Map.of("ranges", "1000-1010,1000-1010", "dry_run", true), program);
        ok(preview);
        var apply = new ClearCodeRangesTool().execute(Map.of("ranges", "1000-1010,1000-1010"), program);
        ok(apply);
        assertNull(program.getListing().getInstructionAt(at("1000")));
        assertNull(program.getListing().getDefinedDataAt(at("1008")));
        assertNull(program.getFunctionManager().getFunctionAt(at("1000")));
        assertTrue(text(apply).contains("Functions cleared: 1"), text(apply));
    }
    @Test void selectorsRejectDuplicateNamesAndExactIdTargetsOnlyIntendedDatabase() throws Exception {
        ProgramDB other = makeProgram();
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend() {
            @Override public List<Program> getAllOpenPrograms() { return List.of(program, other); }
        };
        try {
            var args = Map.<String,Object>of("target_program", program.getName(), "addresses", List.of("1000"));
            assertTrue(new CreateFunctionsAtAddressesTool().execute(args, program, backend).isError());
            assertTrue(new BulkTransferLabelsTool().execute(Map.of("target_program", program.getName(),
                "transfers", List.of(Map.of("target_addr", "1000", "name", "renamed"))), program, backend).isError());
            assertTrue(new BulkRegionTransferTool().execute(Map.of("source_program", program.getName(),
                "target_program", ProgramIdentity.id(other)), program, backend).isError());
            assertTrue(new StringAnchorMatcherTool().execute(Map.of("source_program", program.getName(),
                "target_program", ProgramIdentity.id(other)), program, backend).isError());
            ok(new StringAnchorMatcherTool().execute(Map.of("source_program", ProgramIdentity.id(program),
                "target_program", ProgramIdentity.id(other)), program, backend));
            ok(new CreateFunctionsAtAddressesTool().execute(Map.of("target_program", ProgramIdentity.id(other),
                "addresses", List.of("1000")), program, backend));
            assertNull(program.getFunctionManager().getFunctionAt(at("1000")));
            assertNotNull(other.getFunctionManager().getFunctionAt(other.getAddressFactory().getAddress("1000")));
        } finally { backend.getTaskManager().shutdown(); other.release(consumer); }
    }
    @Test void failedCreationBatchRollsBackPreviouslyCreatedFunctionAndDisassembly() {
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend();
        try {
            var result = new CreateFunctionsAtAddressesTool().execute(Map.of("target_program", ProgramIdentity.id(program),
                "addresses", List.of("1000", "9999")), program, backend);
            assertTrue(result.isError(), text(result));
            assertEquals(0, ((Map<?,?>)result.structuredContent()).get("created"));
            assertEquals(1, ((Map<?,?>)result.structuredContent()).get("rolled_back"));
            assertNull(program.getListing().getInstructionAt(at("1000")));
            assertNull(program.getFunctionManager().getFunctionAt(at("1000")));
            assertNull(program.getCurrentTransactionInfo());
        } finally { backend.getTaskManager().shutdown(); }
    }
    @Test void candidateApplyFailureRollsBackEarlierCreation() throws Exception {
        int tx = program.startTransaction("scan fixture");
        try {
            program.getMemory().createInitializedBlock("nonexec", at("2000"), 16, (byte)0xc3, TaskMonitor.DUMMY, false);
            new ghidra.app.cmd.disassemble.DisassembleCommand(at("1000"), new AddressSet(at("1000")), false).applyTo(program);
            program.getReferenceManager().addMemoryReference(at("1000"), at("1010"), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
            program.getReferenceManager().addMemoryReference(at("1000"), at("2000"), RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 1);
        } finally { program.endTransaction(tx, true); }
        var result = new ScanFunctionCandidatesTool().execute(Map.of("ranges", "1000-2010", "candidate_kind", "call_targets", "mode", "apply"), program);
        assertTrue(result.isError(), text(result));
        assertEquals(0, ((Map<?,?>)result.structuredContent()).get("created"));
        assertEquals(1, ((Map<?,?>)result.structuredContent()).get("rolled_back"));
        assertNull(program.getFunctionManager().getFunctionAt(at("1010")));
        assertNull(program.getListing().getInstructionAt(at("1010")));
        assertNotNull(program.getListing().getInstructionAt(at("1000")));
    }
    @Test void regionTransferRollsBackCreatedFunctionsOnLaterVerificationMismatch() throws Exception {
        regionRollback(false);
    }
    @Test void regionTransferRollsBackOnNativeCreationFailureAndCanCommitVerifiedBatch() throws Exception {
        regionRollback(true);
    }
    private void regionRollback(boolean obstructCreation) throws Exception {
        ProgramDB target = makeProgram();
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend() {
            @Override public List<Program> getAllOpenPrograms() { return List.of(program, target); }
        };
        try {
            int tx = program.startTransaction("region source fixture");
            try {
                program.getFunctionManager().createFunction("known_first", at("1000"), new AddressSet(at("1000")), SourceType.USER_DEFINED);
                program.getFunctionManager().createFunction("known_second", at("1010"),
                    new AddressSet(at("1010"), at(obstructCreation ? "1010" : "1013")), SourceType.USER_DEFINED);
            } finally { program.endTransaction(tx, true); }
            if (obstructCreation) {
                int targetTx = target.startTransaction("obstruct fixture");
                try { target.getListing().createData(at("1010"), DWordDataType.dataType); }
                finally { target.endTransaction(targetTx, true); }
            }
            var args = new HashMap<String,Object>(Map.of("source_program", ProgramIdentity.id(program),
                "target_program", ProgramIdentity.id(target), "start_address", "1000", "end_address", "1020", "code_offset", 0));
            var result = new BulkRegionTransferTool().execute(args, program, backend);
            assertTrue(result.isError(), text(result));
            Map<?,?> body = (Map<?,?>)result.structuredContent();
            assertEquals(0, body.get("matched")); assertEquals(0, body.get("functions_created"));
            assertEquals(1, body.get("labels_rolled_back"));
            assertEquals(obstructCreation ? 1 : 2, body.get("functions_rolled_back"));
            assertNull(target.getFunctionManager().getFunctionAt(at("1000")));
            assertNull(target.getListing().getInstructionAt(at("1000")));
            assertNull(target.getFunctionManager().getFunctionAt(at("1010")));
            assertNull(target.getListing().getInstructionAt(at("1010")));
            if (obstructCreation) assertNotNull(target.getListing().getDefinedDataAt(at("1010")));
            args.put("end_address", "1001");
            ok(new BulkRegionTransferTool().execute(args, program, backend));
            assertEquals("known_first", target.getFunctionManager().getFunctionAt(at("1000")).getName());
        } finally { backend.getTaskManager().shutdown(); target.release(consumer); }
    }
    @Test void explicitTargetLeaseSurvivesGuiConsumerReleaseDuringNativeWrite() throws Exception {
        var language = program.getLanguage();
        ProgramDB target = new ProgramDB("leased-target", language, language.getDefaultCompilerSpec(), consumer) {
            @Override public int startTransaction(String description) {
                if (description.equals("Create Functions at Addresses")) {
                    release(consumer);
                    assertFalse(isClosed(), "tool must own target before its GUI consumer releases it");
                }
                return super.startTransaction(description);
            }
        };
        int tx = target.startTransaction("lease fixture");
        try { target.getMemory().createInitializedBlock("text", at("1000"), 16, (byte)0xc3, TaskMonitor.DUMMY, false).setExecute(true); }
        finally { target.endTransaction(tx, true); }
        GhidrAssistMCPBackend backend = new GhidrAssistMCPBackend() {
            @Override public List<Program> getAllOpenPrograms() { return List.of(program, target); }
        };
        try {
            ok(new CreateFunctionsAtAddressesTool().execute(Map.of("target_program", ProgramIdentity.id(target), "addresses", List.of("1000")), program, backend));
            assertTrue(target.isClosed(), "tool lease must release after actual execution");
        } finally {
            backend.getTaskManager().shutdown();
            if (!target.isClosed() && target.isUsedBy(consumer)) target.release(consumer);
        }
    }
    @Test void bothVariableToolsPersistRetypeAndInvalidTypeLeavesOriginal() throws Exception {
        int tx = program.startTransaction("local fixture");
        try {
            var function = program.getFunctionManager().createFunction("local_fixture", at("1000"), new AddressSet(at("1000")), SourceType.USER_DEFINED);
            function.addLocalVariable(new LocalVariableImpl("local_value", IntegerDataType.dataType, -4, program), SourceType.USER_DEFINED);
        } finally { program.endTransaction(tx, true); }
        var args = Map.<String,Object>of("function_name", "local_fixture", "variable_name", "local_value", "data_type", "float");
        ok(new SetLocalVariableTypeTool(null).execute(args, program));
        assertEquals("float", program.getFunctionManager().getFunctionAt(at("1000")).getLocalVariables()[0].getDataType().getName());
        ok(new VariablesTool(null).execute(Map.of("action", "retype", "function_name", "local_fixture", "variable_name", "local_value", "data_type", "int"), program));
        assertEquals("int", program.getFunctionManager().getFunctionAt(at("1000")).getLocalVariables()[0].getDataType().getName());
        assertTrue(new VariablesTool(null).execute(Map.of("action", "retype", "function_name", "local_fixture", "variable_name", "local_value", "data_type", "NoSuchType"), program).isError());
        assertEquals("int", program.getFunctionManager().getFunctionAt(at("1000")).getLocalVariables()[0].getDataType().getName());
    }
    @Test void typeCreationRequiresExplicitReplacementForStructuresEnumsAndTypedefs() {
        TypesTool tool = new TypesTool();
        ok(tool.execute(Map.of("action", "create_struct", "name", "Existing", "size", 4), program));
        assertTrue(tool.execute(Map.of("action", "create_struct", "name", "Existing", "size", 8), program).isError());
        assertEquals(4, program.getDataTypeManager().getDataType("/Existing").getLength());
        ok(tool.execute(Map.of("action", "create_struct", "name", "Existing", "size", 8, "conflict_policy", "replace"), program));
        assertEquals(8, program.getDataTypeManager().getDataType("/Existing").getLength());
        ok(tool.execute(Map.of("action", "create_enum", "name", "Values", "values", Map.of("OLD", 1)), program));
        assertTrue(tool.execute(Map.of("action", "create_enum", "name", "Values", "values", Map.of("NEW", 2)), program).isError());
        assertEquals(1, ((ghidra.program.model.data.Enum)program.getDataTypeManager().getDataType("/Values")).getValue("OLD"));
        ok(tool.execute(Map.of("action", "create_typedef", "name", "Alias", "base_type", "int", "category", "/User"), program));
        assertTrue(tool.execute(Map.of("action", "create_typedef", "name", "Alias", "base_type", "float", "category", "/User"), program).isError());
        assertEquals("int", ((TypeDef)program.getDataTypeManager().getDataType("/User/Alias")).getBaseDataType().getName());
    }
    @Test void decompilerOnlySymbolIsPersistedByHighFunctionDatabaseUpdate() throws Exception {
        int tx = program.startTransaction("decompiler fixture");
        try {
            program.getMemory().setBytes(at("1000"), new byte[] {(byte)0x8b, 0x44, 0x24, 0x04, (byte)0x83, (byte)0xc0, 0x01, (byte)0xc3});
            assertTrue(new ghidra.app.cmd.disassemble.DisassembleCommand(at("1000"), null, true).applyTo(program));
            assertTrue(new ghidra.app.cmd.function.CreateFunctionCmd(at("1000")).applyTo(program));
        } finally { program.endTransaction(tx, true); }
        Function function = program.getFunctionManager().getFunctionAt(at("1000"));
        assertEquals(0, function.getParameterCount(), "parameter must initially exist only in decompiler output");
        var service = new ghidrassistmcp.decompiler.DecompilerService(p -> null);
        String name = null;
        try (var session = service.open(program)) {
            var result = session.decompiler().decompileFunction(function, 30, TaskMonitor.DUMMY);
            assertTrue(result.decompileCompleted(), result.getErrorMessage());
            var symbols = result.getHighFunction().getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) { var symbol = symbols.next(); if (symbol.isParameter()) { name = symbol.getName(); break; } }
        }
        assertNotNull(name, "fixture should infer a stack parameter");
        ok(new SetLocalVariableTypeTool(service).execute(Map.of("function_name", "1000", "variable_name", name, "data_type", "float"), program));
        assertEquals(1, function.getParameterCount());
        assertEquals("float", function.getParameter(0).getDataType().getName());
    }
    @Test void parserConflictsAndInvalidSyntaxLeaveOriginalTypesIntact() {
        StructTool tool = new StructTool(null);
        ok(tool.execute(Map.of("action", "create", "c_definition", "struct Parsed { int original; };"), program));
        assertTrue(tool.execute(Map.of("action", "create", "c_definition", "struct Parsed { char replacement; };"), program).isError());
        Structure original = (Structure)program.getDataTypeManager().getDataType("/Parsed");
        assertEquals(4, original.getLength()); assertEquals("original", original.getComponent(0).getFieldName());
        assertTrue(tool.execute(Map.of("action", "create", "c_definition", "struct Parsed { int broken !!!; };"), program).isError());
        assertEquals("original", ((Structure)program.getDataTypeManager().getDataType("/Parsed")).getComponent(0).getFieldName());
        ok(tool.execute(Map.of("action", "create", "c_definition", "struct Parsed { char replacement; };", "conflict_policy", "replace"), program));
        assertEquals("replacement", ((Structure)program.getDataTypeManager().getDataType("/Parsed")).getComponent(0).getFieldName());
    }
    @Test void invalidImageBasePropagatesAndRawImportDoesNotSave() throws Exception {
        var original = program.getImageBase();
        assertThrows(IllegalArgumentException.class, () -> ImportFileTool.applyBaseAddress(program, "invalid"));
        assertThrows(IllegalArgumentException.class, () -> ImportFileTool.applyBaseAddress(program, "100000000"));
        assertEquals(original, program.getImageBase()); assertNull(program.getCurrentTransactionInfo());
        var project = ghidra.base.project.GhidraProject.createProject(temp.toString(), "ImportFixture", false);
        try {
            File raw = Files.write(temp.resolve("fixture.bin"), new byte[] {(byte)0xc3}).toFile();
            var method = ImportFileTool.class.getDeclaredMethod("importWithLanguage", File.class, ghidra.framework.model.Project.class,
                String.class, String.class, String.class, String.class, String.class, boolean.class, boolean.class,
                ghidra.app.util.importer.MessageLog.class, ghidra.framework.plugintool.PluginTool.class);
            method.setAccessible(true);
            var failure = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> method.invoke(new ImportFileTool(), raw,
                project.getProject(), "/", "x86:LE:32:default", program.getCompilerSpec().getCompilerSpecID().toString(), "invalid", "must_not_save", false, true,
                new ghidra.app.util.importer.MessageLog(), null));
            assertInstanceOf(IllegalArgumentException.class, failure.getCause());
            assertNull(project.getProjectData().getRootFolder().getFile("must_not_save"));
        } finally { project.close(); }
        ImportFileTool.applyBaseAddress(program, "4000");
        assertEquals("00004000", program.getImageBase().toString());
    }
    private static String text(McpSchema.CallToolResult result) { return result.content().toString(); }
    private static void ok(McpSchema.CallToolResult result) { assertFalse(Boolean.TRUE.equals(result.isError()), text(result)); }
}
