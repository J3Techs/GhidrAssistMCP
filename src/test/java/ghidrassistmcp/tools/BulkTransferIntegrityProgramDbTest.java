package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidrassistmcp.ProgramIdentity;
import io.modelcontextprotocol.spec.McpSchema;
import org.junit.jupiter.api.Test;

/** Root integration tests exercise the public transfer tool against a disposable database. */
class BulkTransferIntegrityProgramDbTest {
    @Test void defaultPolicyPreservesAnalystNameAndSignature() throws Exception {
        try (var f = new Fixture()) {
            assertFalse(new SetFunctionPrototypeTool().execute(Map.of("function_address", "1000",
                "prototype", "int analyst(int original)"), f.program).isError());
            String before = f.function.getPrototypeString(false, false);
            var result = f.apply(Map.of("target_addr", "1000", "name", "replacement",
                "prototype", "void replacement(void)"), Map.of());
            assertFalse(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
            assertEquals("analyst", f.function.getName());
            assertEquals(before, f.function.getPrototypeString(false, false));
        }
    }

    @Test void sameNameStillAppliesDefaultOriginPrototype() throws Exception {
        try (var f = new Fixture()) {
            assertEquals(SourceType.DEFAULT, f.function.getSignatureSource());
            var result = f.apply(Map.of("target_addr", "1000", "name", "analyst",
                "prototype", "int analyst(int value)"), Map.of());
            assertFalse(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
            assertEquals("int analyst(int value)", f.function.getPrototypeString(false, false));
        }
    }

    @Test void invalidPrototypeDryRunDoesNotChangeLiveTypesOrName() throws Exception {
        try (var f = new Fixture()) {
            long revision = f.program.getModificationNumber();
            int types = f.program.getDataTypeManager().getDataTypeCount(true);
            var result = f.apply(Map.of("target_addr", "1000", "name", "replacement",
                "prototype", "invalid invalid ((("), Map.of("dry_run", true, "name_policy", "replace"));
            var body = (Map<?, ?>) result.structuredContent();
            assertNotNull(body);
            assertTrue(String.valueOf(body).contains("failed"));
            assertEquals(revision, f.program.getModificationNumber());
            assertEquals(types, f.program.getDataTypeManager().getDataTypeCount(true));
            assertEquals("analyst", f.function.getName());
            assertEquals(0, ((Number)((Map<?, ?>)body.get("counts")).get("committed")).intValue());
        }
    }

    @Test void previewCountsNoCommitsAndStaleTokenCannotApply() throws Exception {
        try (var f = new Fixture()) {
            var row = Map.<String, Object>of("target_addr", "1000", "name", "replacement");
            var preview = f.apply(row, Map.of("dry_run", true, "name_policy", "replace"));
            var body = (Map<?, ?>)preview.structuredContent();
            assertFalse(Boolean.TRUE.equals(preview.isError()), () -> preview.content().toString());
            assertEquals(0, ((Number)((Map<?, ?>)body.get("counts")).get("committed")).intValue());
            assertEquals(1, ((Number)((Map<?, ?>)body.get("counts")).get("would_commit")).intValue());
            int tx = f.program.startTransaction("intervening edit");
            f.function.setComment("analyst changed this after preview");
            f.program.endTransaction(tx, true);
            var result = f.apply(row, Map.of("name_policy", "replace", "preview_token", body.get("preview_token")));
            assertTrue(result.isError());
            assertEquals("analyst", f.function.getName());
            assertEquals("analyst changed this after preview", f.function.getComment());
        }
    }

    @Test void malformedDryRunIsRejectedBeforeMutation() throws Exception {
        try (var f = new Fixture()) {
            var result = f.apply(Map.of("target_addr", "1000", "name", "replacement"),
                Map.of("dry_run", "true", "name_policy", "replace"));
            assertTrue(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
            assertEquals("analyst", f.function.getName());
        }
    }

    @Test void enclosingTransactionIsPreservedWhenTransferIsRejected() throws Exception {
        try (var f = new Fixture()) {
            int tx = f.program.startTransaction("analyst edit");
            try {
                f.function.setComment("keep this edit");
                var result = f.apply(Map.of("target_addr", "1000", "name", "replacement"),
                    Map.of("name_policy", "replace"));
                assertTrue(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
                assertNotNull(f.program.getCurrentTransactionInfo());
                assertEquals("analyst", f.function.getName());
            } finally { f.program.endTransaction(tx, true); }
            assertEquals("keep this edit", f.function.getComment());
        }
    }

    @Test void racingTransactionIsNotAbortedByStaleRevisionRejection() throws Exception {
        try (var f = new Fixture()) {
            var injected = new java.util.concurrent.atomic.AtomicBoolean();
            var foreignTx = new java.util.concurrent.atomic.AtomicInteger(-1);
            var proxy = (ghidra.program.model.listing.Program)java.lang.reflect.Proxy.newProxyInstance(
                ghidra.program.model.listing.Program.class.getClassLoader(),
                new Class<?>[]{ghidra.program.model.listing.Program.class}, (p, method, args) -> {
                    if (method.getName().equals("startTransaction") && injected.compareAndSet(false, true)) {
                        foreignTx.set(f.program.startTransaction("racing analyst transaction"));
                        f.function.setComment("keep racing edit");
                    }
                    try { return method.invoke(f.program, args); }
                    catch (java.lang.reflect.InvocationTargetException e) { throw e.getCause(); }
                });
            try {
                var result = new BulkTransferLabelsTool().execute(Map.of("target_program", ProgramIdentity.id(proxy),
                    "name_policy", "replace", "transfers", List.of(Map.of("target_addr", "1000", "name", "replacement"))), proxy, null);
                assertTrue(injected.get());
                assertTrue(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
                assertEquals("analyst", f.function.getName());
            } finally {
                if (foreignTx.get() >= 0) f.program.endTransaction(foreignTx.get(), true);
            }
            assertEquals("keep racing edit", f.function.getComment(), "rejecting MCP work must not roll back the foreign writer");
        }
    }

    @Test void explicitReplacementUpdatesBothFieldsWithoutParserRenamingOutsidePolicy() throws Exception {
        try (var f = new Fixture()) {
            var result = f.apply(Map.of("target_addr", "1000", "name", "replacement",
                "prototype", "int unrelated_parser_name(int value)"),
                Map.of("name_policy", "replace", "signature_policy", "replace"));
            assertFalse(Boolean.TRUE.equals(result.isError()), () -> result.content().toString());
            assertEquals("replacement", f.function.getName());
            assertEquals("int replacement(int value)", f.function.getPrototypeString(false, false));
        }
    }

    private static final class Fixture implements AutoCloseable {
        final ProgramDB program;
        final Function function;
        Fixture() throws Exception {
            if (!Application.isInitialized()) Application.initializeApplication(new GhidraApplicationLayout(
                new File(System.getProperty("ghidra.install.dir"))), new HeadlessGhidraApplicationConfiguration());
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            program = new ProgramDB("transfer-integration", language, language.getDefaultCompilerSpec(), this);
            var address = program.getAddressFactory().getAddress("1000");
            int tx = program.startTransaction("fixture");
            function = program.getFunctionManager().createFunction("analyst", address, new AddressSet(address), SourceType.USER_DEFINED);
            program.endTransaction(tx, true);
        }
        McpSchema.CallToolResult apply(Map<String, Object> row, Map<String, Object> options) {
            var args = new LinkedHashMap<String, Object>(options);
            args.put("target_program", ProgramIdentity.id(program));
            args.put("transfers", List.of(row));
            return new BulkTransferLabelsTool().execute(args, program, null);
        }
        public void close() { program.release(this); }
    }
}
