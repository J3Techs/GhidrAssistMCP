package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

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
import ghidrassistmcp.tools.TransferPlanSupport.FieldPolicy;
import ghidrassistmcp.tools.TransferPlanSupport.Intent;
import ghidrassistmcp.tools.TransferPlanSupport.Outcome;
import ghidrassistmcp.tools.TransferPlanSupport.ParseOutcome;
import ghidrassistmcp.tools.TransferPlanSupport.PlanRow;

class TransferPlanContractTest {
    private static final Object CONSUMER = new Object();

    @Test
    void sameNamePrototypeIsIntendedWhileRenameIsSkipped() {
        assertEquals(Intent.SKIP, TransferPlanSupport.decideField(true, "foo", "foo", "DEFAULT", FieldPolicy.REPLACE));
        assertEquals(Intent.SKIP, TransferPlanSupport.decideField(true, "foo", "foo", "USER_DEFINED", FieldPolicy.DEFAULT_ONLY));
        assertEquals(Intent.APPLY, TransferPlanSupport.decideField(true, "int foo(int)", "undefined foo()",
            "DEFAULT", FieldPolicy.DEFAULT_ONLY));
        assertEquals(Intent.APPLY, TransferPlanSupport.decideField(true, "int foo(int)", "undefined foo()",
            "USER_DEFINED", FieldPolicy.REPLACE));
    }

    @Test
    void defaultOnlyPreservesAnalystNameAndSignatureWhileReplaceApplies() {
        assertEquals(Intent.PRESERVE, TransferPlanSupport.decideField(true, "new", "old", "USER_DEFINED", FieldPolicy.DEFAULT_ONLY));
        assertEquals(Intent.PRESERVE, TransferPlanSupport.decideField(true, "int x()", "void y()", "IMPORTED", FieldPolicy.DEFAULT_ONLY));
        assertEquals(Intent.PRESERVE, TransferPlanSupport.decideField(true, "int x()", "void y()", "ANALYSIS", FieldPolicy.DEFAULT_ONLY));
        assertEquals(Intent.APPLY, TransferPlanSupport.decideField(true, "new", "old", "DEFAULT", FieldPolicy.DEFAULT_ONLY));
        assertEquals(Intent.APPLY, TransferPlanSupport.decideField(true, "new", "old", "USER_DEFINED", FieldPolicy.REPLACE));
        assertEquals(Intent.APPLY, TransferPlanSupport.decideField(true, "int x()", "void y()", "IMPORTED", FieldPolicy.REPLACE));
        assertEquals(Intent.SKIP, TransferPlanSupport.decideField(false, "int x()", "void y()", "DEFAULT", FieldPolicy.REPLACE));
    }

    @Test
    void prototypeParseFailureDoesNotMarkTypesChanged() {
        ParseOutcome failed = TransferPlanSupport.parseFailure("syntax error");
        assertTrue(failed.failed());
        assertFalse(failed.typesChanged);
        assertFalse(failed.ok());
        assertEquals("syntax error", failed.error);
        assertFalse(TransferPlanSupport.parseNotRequested().typesChanged);
        assertFalse(TransferPlanSupport.parseOk("int foo(void)").typesChanged);
    }

    @Test
    void nativeCommandFalseOrStatusErrorIsFailure() {
        assertTrue(TransferPlanSupport.nativeCommandFailed(false, null));
        assertTrue(TransferPlanSupport.nativeCommandFailed(false, "Command failed"));
        assertTrue(TransferPlanSupport.nativeCommandFailed(true, "Error applying signature"));
        assertTrue(TransferPlanSupport.nativeCommandFailed(true, "ApplyFunctionSignatureCmd failed"));
        assertFalse(TransferPlanSupport.nativeCommandFailed(true, null));
        assertFalse(TransferPlanSupport.nativeCommandFailed(true, ""));
        assertEquals("ApplyFunctionSignatureCmd returned false",
            TransferPlanSupport.nativeCommandMessage(false, null));
    }

    @Test
    void nonBooleanDryRunAndPolicyArgsAreRejectedNotCoerced() {
        assertFalse(TransferPlanSupport.booleanArg(Map.of(), "dry_run", false));
        assertTrue(TransferPlanSupport.booleanArg(Map.of("dry_run", true), "dry_run", false));
        assertThrows(IllegalArgumentException.class,
            () -> TransferPlanSupport.booleanArg(Map.of("dry_run", "true"), "dry_run", false));
        assertThrows(IllegalArgumentException.class,
            () -> TransferPlanSupport.booleanArg(Map.of("dry_run", 1), "dry_run", false));
        assertThrows(IllegalArgumentException.class,
            () -> TransferPlanSupport.fieldPolicyArg(Map.of("name_policy", true), "name_policy"));
        assertEquals(FieldPolicy.DEFAULT_ONLY, TransferPlanSupport.fieldPolicyArg(Map.of(), "name_policy"));
        String own = "MCP bulk_transfer_labels 123";
        assertTrue(TransferPlanSupport.ownTransactionDescription(own, own));
        assertTrue(TransferPlanSupport.ownTransactionDescription(": " + own, own));
        assertTrue(TransferPlanSupport.ownTransactionDescription("Undoable: " + own, own));
        assertTrue(TransferPlanSupport.ownTransactionDescription("prefix: ", own));
        assertFalse(TransferPlanSupport.ownTransactionDescription("GUI analysis", own));
        assertFalse(TransferPlanSupport.ownTransactionDescription("Another writer started a transaction", own));
        PlanRow preview = new PlanRow();
        preview.status = "would_commit";
        Map<String, Object> counts = TransferPlanSupport.countsFromRows(List.of(preview));
        assertEquals(0, counts.get("committed"));
        assertEquals(1, counts.get("would_commit"));
    }

    @Test
    void stalePreviewTokenIsRejectedAndOmittedTokenStillValidates() {
        Map<String, Object> binding = sampleBinding(3L, FieldPolicy.DEFAULT_ONLY);
        String token = TransferPlanSupport.fingerprint(binding);
        assertTrue(TransferPlanSupport.tokenMatches(null, token));
        assertTrue(TransferPlanSupport.tokenMatches("", token));
        assertTrue(TransferPlanSupport.tokenMatches(token, token));
        assertTrue(TransferPlanSupport.tokenMatches(token.toUpperCase(), token));
        assertFalse(TransferPlanSupport.tokenMatches("0".repeat(64), token));
        TransferPlanSupport.verifyPreviewToken(null, token);
        TransferPlanSupport.verifyPreviewToken(token, token);
        IllegalStateException stale = assertThrows(IllegalStateException.class,
            () -> TransferPlanSupport.verifyPreviewToken("0".repeat(64), token));
        assertTrue(stale.getMessage().contains("Stale preview_token"));
    }

    @Test
    void dryRunFingerprintIsStableAndPolicyOrModNumberInvalidates() {
        List<Map<String, Object>> ops = List.of(Map.of("target_addr", "0x1000", "name", "foo", "prototype", "int foo(int)"));
        String first = TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
            "unsaved:fixture:1", "42", 7L, FieldPolicy.DEFAULT_ONLY, FieldPolicy.DEFAULT_ONLY, "preserve", true, ops));
        String second = TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
            "unsaved:fixture:1", "42", 7L, FieldPolicy.DEFAULT_ONLY, FieldPolicy.DEFAULT_ONLY, "preserve", true, ops));
        assertEquals(first, second);
        assertEquals(64, first.length());
        assertEquals(first, first.toLowerCase());
        assertNotEquals(first, TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
            "unsaved:fixture:1", "42", 8L, FieldPolicy.DEFAULT_ONLY, FieldPolicy.DEFAULT_ONLY, "preserve", true, ops)));
        assertNotEquals(first, TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
            "unsaved:fixture:1", "42", 7L, FieldPolicy.REPLACE, FieldPolicy.DEFAULT_ONLY, "preserve", true, ops)));
        assertNotEquals(first, TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
            "unsaved:fixture:1", "42", 7L, FieldPolicy.DEFAULT_ONLY, FieldPolicy.REPLACE, "preserve", true, ops)));
        assertNotEquals(first, TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
            "unsaved:fixture:1", "42", 7L, FieldPolicy.DEFAULT_ONLY, FieldPolicy.DEFAULT_ONLY, "replace", true, ops)));
        assertNotEquals(first, TransferPlanSupport.fingerprint(TransferPlanSupport.previewBinding(
            "unsaved:fixture:1", "42", 7L, FieldPolicy.DEFAULT_ONLY, FieldPolicy.DEFAULT_ONLY, "preserve", false, ops)));
    }

    @Test
    void wholeCallRollbackCountsCommittedRowsAsRolledBack() {
        PlanRow first = applyRow(0, "0x1000", "one");
        PlanRow second = applyRow(1, "0x2000", "two");
        PlanRow third = applyRow(2, "0x3000", "three");
        TransferPlanSupport.markWholeCallRollback(List.of(first, second, third), 1, "ApplyFunctionSignatureCmd returned false");
        assertEquals("rolled_back", first.status);
        assertEquals(Outcome.ROLLED_BACK, first.nameOutcome);
        assertEquals("failed", second.status);
        assertEquals(Outcome.FAILED, second.signatureOutcome);
        assertEquals("skipped", third.status);
        assertEquals(Outcome.SKIPPED, third.nameOutcome);
        Map<String, Object> counts = TransferPlanSupport.countsFromRows(List.of(first, second, third));
        assertEquals(0, counts.get("committed"));
        assertEquals(1, counts.get("rolled_back"));
        assertEquals(1, counts.get("failed"));
        assertEquals(1, counts.get("skipped"));
        assertEquals(TransferPlanSupport.wholeCallRollbackCounts(2, 1, 0, 3),
            TransferPlanSupport.counts(0, 0, 0, 3, 1, 2));
    }

    @Test
    void outputSchemaExposesPlanCountsAndPreviewToken() {
        Map<String, Object> schema = new BulkTransferLabelsTool().getOutputSchema();
        assertEquals("object", schema.get("type"));
        @SuppressWarnings("unchecked")
        Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
        assertTrue(properties.containsKey("target_program"));
        assertTrue(properties.containsKey("dry_run"));
        assertTrue(properties.containsKey("items"));
        assertTrue(properties.containsKey("counts"));
        assertTrue(properties.containsKey("preview_token"));
        assertTrue(properties.containsKey("name_policy"));
        assertTrue(properties.containsKey("signature_policy"));
        assertTrue(properties.containsKey("types_changed"));
        @SuppressWarnings("unchecked")
        List<String> required = (List<String>) schema.get("required");
        assertTrue(required.contains("preview_token"));
        assertTrue(required.contains("counts"));
        assertTrue(required.contains("items"));
        @SuppressWarnings("unchecked")
        Map<String, Object> counts = (Map<String, Object>) properties.get("counts");
        @SuppressWarnings("unchecked")
        Map<String, Object> countProps = (Map<String, Object>) counts.get("properties");
        for (String key : List.of("committed", "would_commit", "preserved", "skipped", "failed", "rolled_back")) {
            assertTrue(countProps.containsKey(key), key);
        }
        assertEquals("bulk_transfer_labels", new BulkTransferLabelsTool().getName());
        assertTrue(new BulkTransferLabelsTool().getDescription().contains("default_only"));
    }

    @Test
    void isolatedParseFailureLeavesProgramTypesUnchanged() throws Exception {
        Program p = program();
        try {
            Function f = function(p);
            int before = countTypes(p);
            long mod = p.getModificationNumber();
            var result = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "name_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name",
                    "prototype", "not a prototype (("))), p, null);
            assertTrue(result.isError(), () -> result.content().toString());
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) result.structuredContent();
            assertEquals(Boolean.FALSE, body.get("types_changed"));
            assertEquals("none", body.get("mutation"));
            assertEquals(before, countTypes(p));
            assertEquals(mod, p.getModificationNumber());
            assertEquals("old_name", f.getName());
        } finally {
            p.release(CONSUMER);
        }
    }

    @Test
    void sameNamePrototypeChangeDoesNotRequireRename() throws Exception {
        Program p = program();
        try {
            Function f = function(p);
            String before = f.getPrototypeString(false, false);
            var result = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "signature_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "old_name",
                    "prototype", "int old_name(int value)"))), p, null);
            assertFalse(result.isError(), () -> result.content().toString());
            assertEquals("old_name", f.getName());
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) result.structuredContent();
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> items = (List<Map<String, Object>>) body.get("items");
            @SuppressWarnings("unchecked")
            Map<String, Object> intended = (Map<String, Object>) items.get(0).get("intended");
            assertEquals("skip", intended.get("name"));
            assertEquals("apply", intended.get("signature"));
            assertNotEquals(before, f.getPrototypeString(false, false));
        } finally {
            p.release(CONSUMER);
        }
    }

    @Test
    void defaultOnlyPreservesUserDefinedNameAndReplaceOverwrites() throws Exception {
        Program p = program();
        try {
            Function f = function(p);
            var preserved = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            assertFalse(preserved.isError(), () -> preserved.content().toString());
            assertEquals("old_name", f.getName());
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) preserved.structuredContent();
            @SuppressWarnings("unchecked")
            Map<String, Object> counts = (Map<String, Object>) body.get("counts");
            assertEquals(1, counts.get("preserved"));
            var replaced = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "name_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            assertFalse(replaced.isError(), () -> replaced.content().toString());
            assertEquals("new_name", f.getName());
        } finally {
            p.release(CONSUMER);
        }
    }

    @Test
    void stalePreviewTokenFailsBeforeMutationAndOmittedTokenApplies() throws Exception {
        Program p = program();
        try {
            Function f = function(p);
            var dry = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "dry_run", true,
                "name_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            assertFalse(dry.isError(), () -> dry.content().toString());
            @SuppressWarnings("unchecked")
            Map<String, Object> dryBody = (Map<String, Object>) dry.structuredContent();
            String token = (String) dryBody.get("preview_token");
            assertNotNull(token);
            assertEquals(64, token.length());
            assertEquals("old_name", f.getName());
            var stale = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "name_policy", "replace",
                "preview_token", "0".repeat(64),
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            assertTrue(stale.isError());
            assertTrue(stale.content().toString().contains("Stale preview_token"));
            assertEquals("old_name", f.getName());
            var matched = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "name_policy", "replace",
                "preview_token", token,
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            assertFalse(matched.isError(), () -> matched.content().toString());
            assertEquals("new_name", f.getName());
            var omitted = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "name_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "direct_apply"))), p, null);
            assertFalse(omitted.isError(), () -> omitted.content().toString());
            assertEquals("direct_apply", f.getName());
        } finally {
            p.release(CONSUMER);
        }
    }

    @Test
    void dryRunFingerprintStableUntilPolicyOrModificationChanges() throws Exception {
        Program p = program();
        try {
            var first = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "dry_run", true,
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            var second = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "dry_run", true,
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            @SuppressWarnings("unchecked")
            String token1 = (String) ((Map<String, Object>) first.structuredContent()).get("preview_token");
            @SuppressWarnings("unchecked")
            String token2 = (String) ((Map<String, Object>) second.structuredContent()).get("preview_token");
            assertEquals(token1, token2);
            var policy = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "dry_run", true,
                "name_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            @SuppressWarnings("unchecked")
            String tokenPolicy = (String) ((Map<String, Object>) policy.structuredContent()).get("preview_token");
            assertNotEquals(token1, tokenPolicy);
            int tx = p.startTransaction("bump");
            function(p).setComment("mod");
            p.endTransaction(tx, true);
            var afterMod = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "dry_run", true,
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            @SuppressWarnings("unchecked")
            String tokenMod = (String) ((Map<String, Object>) afterMod.structuredContent()).get("preview_token");
            assertNotEquals(token1, tokenMod);
        } finally {
            p.release(CONSUMER);
        }
    }

    @Test
    void mixedRowApplyTimeFailureRollsBackPriorMutations() throws Exception {
        Program p = program();
        try {
            Address second = p.getAddressFactory().getAddress("0x1080");
            int tx = p.startTransaction("second function");
            p.getFunctionManager().createFunction("other", second, new AddressSet(second), SourceType.USER_DEFINED);
            p.endTransaction(tx, true);
            Function first = function(p);
            Function other = p.getFunctionManager().getFunctionAt(second);
            var result = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "name_policy", "replace",
                "transfers", List.of(
                    Map.of("target_addr", "0x1000", "name", "committed_then_rolled_back"),
                    Map.of("target_addr", "0x1080", "name", "not a valid name!!!"))), p, null);
            assertTrue(result.isError());
            assertEquals("other", other.getName());
            assertEquals("old_name", first.getName());
            @SuppressWarnings("unchecked")
            Map<String, Object> body = (Map<String, Object>) result.structuredContent();
            @SuppressWarnings("unchecked")
            Map<String, Object> counts = (Map<String, Object>) body.get("counts");
            assertEquals(0, counts.get("committed"));
            assertTrue(((Number) counts.get("rolled_back")).intValue() >= 1
                || ((Number) counts.get("failed")).intValue() >= 1);
            assertEquals("rolled_back", body.get("mutation"));
            assertEquals(Boolean.FALSE, body.get("types_changed"));
        } finally {
            p.release(CONSUMER);
        }
    }

    @Test
    void enclosingTransactionIsRejectedAndDryRunDoesNotStartOne() throws Exception {
        Program p = program();
        try {
            Function f = function(p);
            var dry = new BulkTransferLabelsTool().execute(Map.of(
                "target_program", "fixture",
                "dry_run", true,
                "name_policy", "replace",
                "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
            assertFalse(dry.isError(), () -> dry.content().toString());
            assertNull(p.getCurrentTransactionInfo());
            assertEquals("old_name", f.getName());
            int tx = p.startTransaction("outer");
            try {
                var blocked = new BulkTransferLabelsTool().execute(Map.of(
                    "target_program", "fixture",
                    "name_policy", "replace",
                    "transfers", List.of(Map.of("target_addr", "0x1000", "name", "new_name"))), p, null);
                assertTrue(blocked.isError());
                assertTrue(blocked.content().toString().contains("enclosing transaction"));
                assertEquals("old_name", f.getName());
            } finally {
                p.endTransaction(tx, false);
            }
        } finally {
            p.release(CONSUMER);
        }
    }

    private static PlanRow applyRow(int index, String addr, String name) {
        PlanRow row = new PlanRow();
        row.index = index;
        row.targetAddr = addr;
        row.requestedName = name;
        row.nameIntent = Intent.APPLY;
        row.signatureIntent = Intent.APPLY;
        row.status = "would_commit";
        return row;
    }

    private static Map<String, Object> sampleBinding(long modificationNumber, FieldPolicy namePolicy) {
        return TransferPlanSupport.previewBinding("prog", "1", modificationNumber, namePolicy,
            FieldPolicy.DEFAULT_ONLY, "preserve", true,
            List.of(Map.of("target_addr", "0x1000", "name", "foo")));
    }

    private static Program program() throws Exception {
        if (!Application.isInitialized()) {
            Application.initializeApplication(
                new GhidraApplicationLayout(new File(System.getProperty("ghidra.install.dir"))),
                new HeadlessGhidraApplicationConfiguration());
        }
        var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
        Program p = new ProgramDB("fixture", lang, lang.getDefaultCompilerSpec(), CONSUMER);
        int tx = p.startTransaction("fixture");
        try {
            Address a = p.getAddressFactory().getAddress("0x1000");
            p.getMemory().createInitializedBlock("text", a, 0x100, (byte) 0x90, ghidra.util.task.TaskMonitor.DUMMY, false);
            p.getDataTypeManager().addDataType(ghidra.program.model.data.ShortDataType.dataType,
                ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);
            p.getFunctionManager().createFunction("old_name", a, new AddressSet(a), SourceType.USER_DEFINED);
            p.endTransaction(tx, true);
            return p;
        } catch (Exception e) {
            p.endTransaction(tx, false);
            p.release(CONSUMER);
            throw e;
        }
    }

    private static Function function(Program p) {
        return p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress("0x1000"));
    }

    private static int countTypes(Program p) {
        int count = 0;
        var types = p.getDataTypeManager().getAllDataTypes();
        while (types.hasNext()) {
            types.next();
            count++;
        }
        return count;
    }
}
