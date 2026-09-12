package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.List;
import java.util.stream.Collectors;
import java.io.File;
import java.nio.file.Path;

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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.protocol.QueryName;
import ghidra.features.bsim.query.protocol.ResponseName;

class BsimCorpusOperationsTest {
    private static final Object CONSUMER = new Object();

    @BeforeAll
    static void initializeGhidra() throws Exception {
        if (!Application.isInitialized()) Application.initializeApplication(
            new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
            new HeadlessGhidraApplicationConfiguration());
    }
    @Test
    void corpusOperationsExposeStructuredSchemasAndSafetyMetadata() {
        var operations = BsimCorpusOperations.operations();
        var byName = operations.stream().collect(Collectors.toMap(BsimOperation::name, o -> o));
        assertEquals(6, byName.size());
        assertTrue(byName.get("generate_signatures").longRunning());
        assertTrue(byName.get("ingest").properties().get("xml_directory") instanceof Map);
        assertTrue(byName.get("rebuild_corpus").destructive());
        assertTrue(byName.get("remove_executables").destructive());
        assertEquals("destination_database", byName.get("rebuild_corpus").required().get(0));
    }

    @Test
    void removalDefaultsToPreviewAndRequiresExplicitApply() {
        var removal = BsimCorpusOperations.operations().stream()
            .filter(operation -> operation.name().equals("remove_executables")).findFirst().orElseThrow();
        assertFalse(removal.readOnly());
        assertTrue(removal.properties().containsKey("dry_run"));
        assertTrue(removal.properties().containsKey("apply"));
    }

    @Test
    void programToH2ExportSecondIngestAndSeparateRebuild(@TempDir Path temporary) throws Exception {
        GhidraProject project = GhidraProject.createProject(temporary.toString(), "BsimFixture", false);
        Program program = null;
        try {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            program = new ProgramDB("fixture", language, language.getDefaultCompilerSpec(), CONSUMER);
            int tx = program.startTransaction("fixture");
            try {
                Address base = program.getAddressFactory().getAddress("1000");
                program.setExecutablePath("bsim-fixture");
                program.setExecutableMD5("0123456789abcdef0123456789abcdef");
                program.getMemory().createInitializedBlock("text", base, 0x100,
                    (byte) 0x90, TaskMonitor.DUMMY, false).setExecute(true);
                program.getMemory().setBytes(base, new byte[] {(byte) 0x8b, (byte) 0x44, (byte) 0x24,
                    (byte) 0x04, (byte) 0x83, (byte) 0xc0, (byte) 0x07, (byte) 0xc3});
                new DisassembleCommand(base, new AddressSet(base, base.add(7)), false)
                    .applyTo(program, TaskMonitor.DUMMY);
                program.getFunctionManager().createFunction("fixture_main", base,
                    new AddressSet(base, base.add(7)), SourceType.USER_DEFINED);
                program.endTransaction(tx, true);
            } catch (Exception e) { program.endTransaction(tx, false); throw e; }
            project.getProjectData().getRootFolder().createFile("fixture", program, TaskMonitor.DUMMY);
            program.getDomainFile().save(TaskMonitor.DUMMY);

            BsimConnections connections = new BsimConnections(temporary.resolve("settings"));
            try (BsimContext context = new BsimContext(program, null, connections, temporary, null)) {
            String first = temporary.resolve("first").toUri().toString();
            String second = temporary.resolve("second").toUri().toString();
            String rebuilt = temporary.resolve("rebuilt").toUri().toString();
            createDatabase(context, first, "first");
            createDatabase(context, second, "second");
            createDatabase(context, rebuilt, "rebuilt");

            operation("generate_signatures").handler().execute(context,
                Map.of("output_directory", "generated", "database_url", first), TaskMonitor.DUMMY);
            operation("ingest").handler().execute(context,
                Map.of("xml_directory", "generated", "database_url", first), TaskMonitor.DUMMY);
            assertFunction(context, first);
            // Simulate a restart after the database committed but before the client checkpointed.
            Path staged;
            try (var files = java.nio.file.Files.list(temporary.resolve("generated"))) { staged = files.filter(p -> p.toString().endsWith(".xml")).findFirst().orElseThrow(); }
            var journals = new BsimJobs(temporary.resolve("restart-jobs"));
            var interrupted = journals.create("ingest", Map.of("xml_directory", "generated", "database_url", first));
            String unit = "ingest:" + staged.getFileName();
            String hash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(java.nio.file.Files.readAllBytes(staged)));
            interrupted.begin(unit, Map.of("file", staged.toString(), "sha256", hash));
            interrupted.transition("RUNNING", null);
            var recovered = new BsimJobs(temporary.resolve("restart-jobs")).get(interrupted.id());
            assertEquals("INTERRUPTED", recovered.status());
            try (var resumedContext = new BsimContext(program, null, connections, temporary, recovered)) {
                operation("ingest").handler().execute(resumedContext, recovered.arguments(), TaskMonitor.DUMMY);
                assertNotNull(recovered.completed(unit));
                assertFunction(context, first);
                byte[] originalXml = java.nio.file.Files.readAllBytes(staged);
                java.nio.file.Files.writeString(staged, "tampered");
                assertThrows(java.io.IOException.class, () -> operation("ingest").handler().execute(resumedContext, recovered.arguments(), TaskMonitor.DUMMY));
                java.nio.file.Files.write(staged, originalXml);
            }
            BsimOperation queryProgram = BsimQueryOperations.operations().stream()
                .filter(operation -> operation.name().equals("query_program")).findFirst().orElseThrow();
            Map<String, Object> queried = queryProgram.handler().execute(context,
                Map.of("database_url", first, "limit", 10, "similarity", 0.5), TaskMonitor.DUMMY);
            var queryRows = (java.util.List<?>) queried.get("results");
            assertFalse(queryRows.isEmpty(), queried::toString);
            Map<?, ?> firstRow = (Map<?, ?>) queryRows.get(0);
            assertEquals("1000", firstRow.get("source_address"));
            Map<?, ?> match = (Map<?, ?>) firstRow.get("match");
            Map<String, Object> stored = BsimQueryOperations.operations().stream().filter(o -> o.name().equals("get_function")).findFirst().orElseThrow()
                .handler().execute(context, Map.of("database_url", first, "md5", match.get("md5"), "function", match.get("name")), TaskMonitor.DUMMY);
            assertNotNull(stored.get("vector_id"), stored::toString);
            BsimOperation queryVectors = BsimQueryOperations.operations().stream()
                .filter(operation -> operation.name().equals("query_vectors")).findFirst().orElseThrow();
            Map<String, Object> vectorQuery = queryVectors.handler().execute(context,
                Map.of("database_url", first, "vector_ids", List.of(stored.get("vector_id")), "limit", 10),
                TaskMonitor.DUMMY);
            assertFalse(((java.util.List<?>) vectorQuery.get("results")).isEmpty());

            Map<String, Object> exported = operation("export").handler().execute(context,
                Map.of("output_file", "export.xml", "name", "fixture", "database_url", first), TaskMonitor.DUMMY);
            assertTrue(java.nio.file.Files.isRegularFile(Path.of((String) exported.get("path"))));
            operation("ingest").handler().execute(context,
                Map.of("xml_directory", "export.xml", "database_url", second), TaskMonitor.DUMMY);
            assertFunction(context, second);

            connections.configure(Map.of("profile_id", "source", "database_url", first));
            connections.configure(Map.of("profile_id", "destination", "database_url", rebuilt));
            var rebuildResult = operation("rebuild_corpus").handler().execute(context,
                Map.of("source_database", "source", "destination_database", "destination"), TaskMonitor.DUMMY);
            assertEquals(1, rebuildResult.get("copied_executables"), rebuildResult::toString);
            assertFunction(context, rebuilt);

            Map<String, Object> preview = operation("remove_executables").handler().execute(context,
                Map.of("database_url", first, "name", "fixture"), TaskMonitor.DUMMY);
            assertEquals(true, preview.get("preview"));
            assertTrue(((java.util.List<?>) preview.get("candidates")).size() == 1);
            Map<String, Object> removed = operation("remove_executables").handler().execute(context,
                Map.of("database_url", first, "name", "fixture", "apply", true), TaskMonitor.DUMMY);
            assertEquals(1, removed.get("removed"));
            }
        } finally {
            if (program != null && !program.isClosed()) program.release(CONSUMER);
            project.close();
        }
    }

    private static void createDatabase(BsimContext context, String url, String name) throws Exception {
        operation("create_database").handler().execute(context,
            Map.of("database_url", url, "template", "medium_32.xml", "name", name, "owner", "test"),
            TaskMonitor.DUMMY);
    }

    private static void assertFunction(BsimContext context, String url) throws Exception {
        try (FunctionDatabase database = context.database(Map.of("database_url", url))) {
            QueryName query = new QueryName();
            query.spec.exename = "fixture";
            query.maxfunc = 100;
            ResponseName response = BsimSupport.query(database, query);
            assertEquals(1, response.manage.numFunctions(), "BSim corpus function count must be exact");
        }
    }

    private static BsimOperation operation(String name) {
        return BsimCorpusOperations.operations().stream()
            .filter(operation -> operation.name().equals(name)).findFirst()
            .orElseGet(() -> BsimDatabaseOperations.operations().stream()
                .filter(operation -> operation.name().equals(name)).findFirst().orElseThrow());
    }
}
