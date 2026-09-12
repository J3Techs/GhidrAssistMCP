package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * WP08 first-slice contracts. These tests use string language classifiers and
 * must not require Ghidra Application initialization. ProgramDB ARM/x86 mask
 * fixtures are follow-up work; generic instruction-aware masks are deferred.
 */
class MatcherArchitectureContractTest {

    private static final MatcherContracts.LanguageFacts X86 =
        MatcherContracts.LanguageFacts.fromLanguageId("x86:LE:32:default");
    private static final MatcherContracts.LanguageFacts ARM =
        MatcherContracts.LanguageFacts.fromLanguageId("ARM:LE:32:v7");
    private static final MatcherContracts.LanguageFacts THUMB =
        MatcherContracts.LanguageFacts.of("ARM:LE:32:v8T", "ARM", List.of("TMode"));
    private static final MatcherContracts.LanguageFacts VLE_BE =
        MatcherContracts.LanguageFacts.fromLanguageId("PowerPC:BE:32:VLE");
    private static final MatcherContracts.LanguageFacts VLE_LE =
        MatcherContracts.LanguageFacts.fromLanguageId("PowerPC:LE:32:VLE");
    private static final MatcherContracts.LanguageFacts E200_VLE =
        MatcherContracts.LanguageFacts.of("PowerPC:BE:32:e200", "PowerPC", List.of("vle"));

    @Test
    void noneIsAllowedForX86AndArm() {
        assertTrue(MatcherContracts.qualify(MatcherContracts.MaskMode.NONE, X86, X86).allowed());
        assertTrue(MatcherContracts.qualify(MatcherContracts.MaskMode.NONE, ARM, ARM).allowed());
        assertTrue(MatcherContracts.qualify(MatcherContracts.MaskMode.NONE, THUMB, THUMB).allowed());
        assertEquals(MatcherContracts.CompareMode.RAW_BYTES,
            MatcherContracts.qualify(MatcherContracts.MaskMode.NONE, X86, ARM).compareMode());
    }

    @Test
    void autoAndAggressiveAreRejectedForUnsupportedAndMismatchedLanguages() {
        for (MatcherContracts.MaskMode mode : List.of(MatcherContracts.MaskMode.AUTO, MatcherContracts.MaskMode.AGGRESSIVE)) {
            assertRejectedMasked(mode, X86, X86);
            assertRejectedMasked(mode, ARM, ARM);
            assertRejectedMasked(mode, THUMB, THUMB);
            assertRejectedMasked(mode, VLE_BE, X86);
            assertRejectedMasked(mode, VLE_BE, VLE_LE);
            assertRejectedMasked(mode, VLE_BE, E200_VLE);
        }
    }

    @Test
    void autoAndAggressiveRequireProvenBeVleLanguageAndRangeContext() {
        var unknown = VLE_BE;
        assertTrue(MatcherContracts.languageAllowsVleMasks(unknown));
        assertRejectedMasked(MatcherContracts.MaskMode.AUTO, unknown, unknown);
        var proven = VLE_BE.withRangeContext(MatcherContracts.RangeVleContext.VLE_ON);
        var auto = MatcherContracts.qualify(MatcherContracts.MaskMode.AUTO, proven, proven);
        var aggressive = MatcherContracts.qualify(MatcherContracts.MaskMode.AGGRESSIVE, proven, proven);
        assertTrue(auto.allowed());
        assertTrue(aggressive.allowed());
        assertEquals(MatcherContracts.CompareMode.POWERPC_VLE_OPERAND_MASK, auto.compareMode());
        assertRejectedMasked(MatcherContracts.MaskMode.AUTO,
            VLE_LE.withRangeContext(MatcherContracts.RangeVleContext.VLE_ON),
            VLE_LE.withRangeContext(MatcherContracts.RangeVleContext.VLE_ON));
        assertRejectedMasked(MatcherContracts.MaskMode.AUTO, E200_VLE, E200_VLE);
        assertRejectedMasked(MatcherContracts.MaskMode.AUTO,
            E200_VLE.withRangeContext(MatcherContracts.RangeVleContext.VLE_ON),
            E200_VLE.withRangeContext(MatcherContracts.RangeVleContext.VLE_ON));
        assertFalse(MatcherContracts.languageAllowsVleMasks(VLE_LE));
        assertFalse(MatcherContracts.languageAllowsVleMasks(E200_VLE));
        assertFalse(MatcherContracts.isPowerPcVle(
            MatcherContracts.LanguageFacts.fromLanguageId("PowerPC:BE:32:e200")));
    }

    @Test
    void unknownMaskModeIsRejected() {
        var error = assertThrows(IllegalArgumentException.class, () -> MatcherContracts.parseMaskMode("wildcard"));
        assertTrue(error.getMessage().contains("Unknown mask_mode"));
        assertEquals(MatcherContracts.MaskMode.AUTO, MatcherContracts.parseMaskMode(null));
        assertEquals(MatcherContracts.MaskMode.AUTO, MatcherContracts.parseMaskMode(""));
        assertEquals(MatcherContracts.MaskMode.NONE, MatcherContracts.parseMaskMode("None"));
    }

    @Test
    void uniquenessHelperDoesNotTreatACapAsUniqueAndTruncationForcesFalse() {
        assertFalse(MatcherContracts.uniqueBecauseCapped(20, 20));
        assertFalse(MatcherContracts.uniqueBecauseCapped(1, 1));
        assertFalse(MatcherContracts.isUnique(20, 20, false, true, false));
        assertFalse(MatcherContracts.isUnique(1, 20, true, false, false));
        assertFalse(MatcherContracts.isUnique(1, 20, false, true, true));
        assertFalse(MatcherContracts.isUnique(1, 20, false, false, false));
        assertTrue(MatcherContracts.isUnique(1, 20, false, true, false));
        var capped = MatcherContracts.scanStatus(20, 20, true, false, false);
        assertTrue(capped.scanTruncated());
        assertFalse(capped.unique());
        var truncatedOne = MatcherContracts.scanStatus(1, 20, true, false, false);
        assertTrue(truncatedOne.scanTruncated());
        assertFalse(truncatedOne.unique());
    }

    @Test
    void uniqueAnchorRequiresSingleOccurrenceAndSingleFunction() {
        assertTrue(MatcherContracts.uniqueAnchor(1, 1));
        assertFalse(MatcherContracts.uniqueAnchor(2, 1));
        assertFalse(MatcherContracts.uniqueAnchor(1, 2));
        assertFalse(MatcherContracts.uniqueAnchor(2, 2));
    }

    @Test
    void jacksonRoundTripsAnchorTextWithQuotesNewlinesAndUnicode() {
        String text = "line1\n\"quoted\"\t世界";
        Map<String, Object> fields = MatcherContracts.anchorFields(text, 60);
        assertEquals(text, fields.get("anchor_string"));
        assertEquals(Boolean.FALSE, fields.get("anchor_truncated"));
        String json = MatcherContracts.toJson(fields);
        assertTrue(json.contains("\\n") || json.contains("line1"));
        Map<String, Object> roundTrip = MatcherContracts.fromJsonObject(json);
        assertEquals(text, roundTrip.get("anchor_string"));
        assertEquals(fields.get("anchor_preview"), roundTrip.get("anchor_preview"));
        assertEquals(fields.get("anchor_length"), roundTrip.get("anchor_length"));

        String longText = "x".repeat(80) + "\"\n世界";
        Map<String, Object> truncated = MatcherContracts.anchorFields(longText, 60);
        assertEquals(longText, truncated.get("anchor_string"));
        assertEquals(Boolean.TRUE, truncated.get("anchor_truncated"));
        assertEquals(longText.substring(0, 60), truncated.get("anchor_preview"));
        Map<String, Object> truncatedRoundTrip = MatcherContracts.fromJsonObject(MatcherContracts.toJson(truncated));
        assertEquals(longText, truncatedRoundTrip.get("anchor_string"));
        assertEquals(Boolean.TRUE, truncatedRoundTrip.get("anchor_truncated"));
    }

    @Test
    void supportedModeTableAllowsMaskedModesOnlyForPowerPcVle() {
        boolean sawVle = false;
        for (Map<String, Object> row : MatcherContracts.supportedModeTable()) {
            boolean auto = Boolean.TRUE.equals(row.get("mask_mode_auto"));
            boolean aggressive = Boolean.TRUE.equals(row.get("mask_mode_aggressive"));
            boolean none = Boolean.TRUE.equals(row.get("mask_mode_none"));
            assertTrue(none);
            if (String.valueOf(row.get("architecture")).contains("PowerPC")
                    && String.valueOf(row.get("architecture")).contains("VLE")) {
                sawVle = true;
                assertTrue(auto);
                assertTrue(aggressive);
            } else {
                assertFalse(auto);
                assertFalse(aggressive);
            }
        }
        assertTrue(sawVle);
    }

    @Test
    void regionCompareUsesExactBytesForMatchingNonVleAndRejectsMismatchedArchitectures() {
        var x86 = MatcherContracts.regionCompare(X86, X86);
        assertTrue(x86.allowed());
        assertEquals(MatcherContracts.RegionCompareMode.EXACT_BYTES, x86.mode());
        var mismatched = MatcherContracts.regionCompare(X86, ARM);
        assertFalse(mismatched.allowed());
        assertEquals(MatcherContracts.RegionCompareMode.REJECTED, mismatched.mode());
        var unknownVle = MatcherContracts.regionCompare(VLE_BE, VLE_BE);
        assertFalse(unknownVle.allowed(), "unknown per-range VLE context must fail closed");
        var proven = VLE_BE.withRangeContext(MatcherContracts.RangeVleContext.VLE_ON);
        var vle = MatcherContracts.regionCompare(proven, proven);
        assertTrue(vle.allowed());
        assertEquals(MatcherContracts.RegionCompareMode.POWERPC_VLE_OPCODE_MASK, vle.mode());
        assertFalse(MatcherContracts.regionCompare(VLE_BE, VLE_LE).allowed());
    }

    @Test
    void matcherToolsDeclareOutputSchemasWithoutApplicationInit() {
        assertNotNull(new FunctionByteMatcherTool().getOutputSchema());
        assertNotNull(new StringAnchorMatcherTool().getOutputSchema());
        assertNotNull(new BulkRegionTransferTool().getOutputSchema());
        assertTrue(new FunctionByteMatcherTool().isLongRunning());
        assertTrue(new StringAnchorMatcherTool().isLongRunning());
        assertTrue(new FunctionByteMatcherTool().execute(Map.of(), null).isError());
        assertTrue(new StringAnchorMatcherTool().execute(Map.of(), null).isError());
    }

    @Test
    void defaultScanSkipsNonExecutableHashAndUninitializedSpaces() {
        assertTrue(MatcherContracts.isDefaultScanSpace(true, false, true, true));
        assertFalse(MatcherContracts.isDefaultScanSpace(false, false, true, true));
        assertFalse(MatcherContracts.isDefaultScanSpace(true, true, true, true));
        assertFalse(MatcherContracts.isDefaultScanSpace(true, false, false, true));
        assertFalse(MatcherContracts.isDefaultScanSpace(true, false, true, false));
    }

    private static void assertRejectedMasked(MatcherContracts.MaskMode mode,
            MatcherContracts.LanguageFacts source, MatcherContracts.LanguageFacts target) {
        var decision = MatcherContracts.qualify(mode, source, target);
        assertFalse(decision.allowed(), mode + " " + source.languageId() + " -> " + target.languageId());
        assertEquals(MatcherContracts.CompareMode.REJECTED, decision.compareMode());
        assertNotEquals(MatcherContracts.CompareMode.RAW_BYTES, decision.compareMode());
        assertTrue(decision.message().contains("mask_mode=none"));
        assertTrue(decision.message().contains("BSim"));
    }
}
