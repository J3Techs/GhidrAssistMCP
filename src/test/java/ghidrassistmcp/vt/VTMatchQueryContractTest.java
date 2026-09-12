package ghidrassistmcp.vt;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** Query-helper contracts for vt_matches. Markup/save/reopen coverage lives in VTNativeIntegrationTest and is not re-run here. */
class VTMatchQueryContractTest {

    private static VTSupport.MatchQueryKey key(double similarity, double confidence, int setId, String src, String dst) {
        return key(similarity, confidence, setId, src, dst, 0);
    }
    private static VTSupport.MatchQueryKey key(double similarity, double confidence, int setId, String src, String dst, int scanIndex) {
        return new VTSupport.MatchQueryKey(similarity, confidence, setId, src, dst, scanIndex);
    }

    @Test
    void namesPresentVersusMissingStayExplicitNulls() {
        assertEquals("main", VTSupport.namesOrNull("main"));
        assertEquals("FUN_00001000", VTSupport.namesOrNull("FUN_00001000"));
        assertNull(VTSupport.namesOrNull(null));
        assertNull(VTSupport.namesOrNull(""));
        assertNull(VTSupport.namesOrNull("   "));
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("source_name", VTSupport.namesOrNull("src_fn"));
        row.put("source_name_source", VTSupport.namesOrNull("USER_DEFINED"));
        row.put("destination_name", VTSupport.namesOrNull(null));
        row.put("destination_name_source", VTSupport.namesOrNull(""));
        assertEquals("src_fn", row.get("source_name"));
        assertEquals("USER_DEFINED", row.get("source_name_source"));
        assertTrue(row.containsKey("destination_name"));
        assertNull(row.get("destination_name"));
        assertNull(row.get("destination_name_source"));
    }

    @Test
    void statusAndMinScoreFilters() {
        assertTrue(VTSupport.accept("ACCEPTED", 0.9, "accepted", 0.5));
        assertTrue(VTSupport.accept("REJECTED", 1.0, "REJECTED", null));
        assertTrue(VTSupport.accept("AVAILABLE", 0.1, "available", 0.0));
        assertTrue(VTSupport.accept("BLOCKED", 0.8, "blocked", 0.8));
        assertFalse(VTSupport.accept("AVAILABLE", 0.9, "accepted", 0.1));
        assertFalse(VTSupport.accept("ACCEPTED", 0.4, "accepted", 0.5));
        assertFalse(VTSupport.accept("ACCEPTED", null, "accepted", 0.0));
        assertTrue(VTSupport.accept("ACCEPTED", null, "accepted", null));
        assertTrue(VTSupport.acceptMinScore(0.5, 0.5));
        assertFalse(VTSupport.acceptMinScore(Double.NaN, 0.1));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.normalizeStatusFilter("maybe"));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.normalizeStatusFilter(""));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.statusFilter(Map.of("status", 1)));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.minScore(Map.of("min_score", Double.NaN)));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.minScore(Map.of("min_score", "0.5")));
        assertEquals(0.75, VTSupport.minScore(Map.of("min_score", 0.75)));
        assertNull(VTSupport.minScore(Map.of()));
        assertEquals("ACCEPTED", VTSupport.statusFilter(Map.of("status", "accepted")));
        assertEquals("BLOCKED", VTSupport.statusFilter(Map.of("status", "BLOCKED")));
        assertNull(VTSupport.matchSetFilter(Map.of()));
        assertEquals(3, VTSupport.matchSetFilter(Map.of("match_set_id", 3)));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.matchSetFilter(Map.of("match_set_id", -1)));
    }

    @Test
    void equalScoreOrderIsStableAcrossPages() {
        VTSupport.MatchQueryKey a = key(0.9, 1.0, 1, "1000", "2000");
        VTSupport.MatchQueryKey b = key(0.9, 1.0, 1, "1000", "3000");
        VTSupport.MatchQueryKey c = key(0.9, 0.5, 1, "1000", "1000");
        VTSupport.MatchQueryKey d = key(0.8, 9.0, 1, "0000", "0000");
        List<VTSupport.MatchQueryKey> shuffled = new ArrayList<>(List.of(d, b, c, a));
        shuffled.sort(VTSupport::compareKeys);
        assertEquals(List.of(a, b, c, d), shuffled);
        VTSupport.MatchPage first = VTSupport.selectPage(List.of(d, b, c, a), 0, 2);
        VTSupport.MatchPage second = VTSupport.selectPage(List.of(a, d, c, b), 2, 2);
        assertEquals(List.of(a, b), first.items());
        assertEquals(List.of(c, d), second.items());
        assertTrue(first.hasMore());
        assertFalse(second.hasMore());
    }

    @Test
    void duplicateMatchSetIdentitiesRemainDistinct() {
        VTSupport.MatchQueryKey set1 = key(0.95, 2.0, 1, "1000", "2000");
        VTSupport.MatchQueryKey set2 = key(0.95, 2.0, 2, "1000", "2000");
        assertNotEquals(set1, set2);
        List<VTSupport.MatchQueryKey> ordered = new ArrayList<>(List.of(set2, set1));
        ordered.sort(VTSupport::compareKeys);
        assertEquals(List.of(set1, set2), ordered);
        VTSupport.MatchPage page = VTSupport.selectPage(List.of(set2, set1), 0, 10);
        assertEquals(2, page.total());
        assertEquals(List.of(set1, set2), page.items());
    }

    @Test
    void sessionRevisionMismatchInvalidatesPaging() {
        assertTrue(VTSupport.pageInvalidated(1L, 2L));
        assertTrue(VTSupport.pageInvalidated(0L, 1L));
        assertFalse(VTSupport.pageInvalidated(null, 7L));
        assertFalse(VTSupport.pageInvalidated(4L, 4L));
        assertEquals(3L, VTSupport.optionalRevision(Map.of("session_revision", 3)));
        assertNull(VTSupport.optionalRevision(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.optionalRevision(Map.of("session_revision", 1.5)));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.optionalRevision(Map.of("session_revision", -1)));
    }

    @Test
    void pageBoundsDoNotRetainTheFullNativeList() {
        List<VTSupport.MatchQueryKey> keys = new ArrayList<>();
        for (int i = 0; i < 1000; i++) keys.add(key(i / 1000.0, 0, 1, String.format("%04d", i), "dest"));
        assertEquals(15, VTSupport.pageWindowCap(10, 5));
        assertTrue(VTSupport.pageWindowCap(10, 5) < keys.size());
        VTSupport.MatchPage page = VTSupport.selectPage(keys, 10, 5);
        assertEquals(1000, page.total());
        assertEquals(5, page.items().size());
        assertTrue(page.hasMore());
        List<VTSupport.MatchQueryKey> expected = new ArrayList<>(keys);
        expected.sort(VTSupport::compareKeys);
        assertEquals(expected.subList(10, 15), page.items());
        VTSupport.MatchPage empty = VTSupport.selectPage(keys, 1000, 5);
        assertTrue(empty.items().isEmpty());
        assertFalse(empty.hasMore());
        assertEquals(VTSupport.MAX_PAGE_WINDOW, VTSupport.pageWindowCap(VTSupport.MAX_PAGE_WINDOW - 1, 1));
        var huge = assertThrows(IllegalArgumentException.class, () -> VTSupport.pageWindowCap(Integer.MAX_VALUE, 1));
        assertTrue(huge.getMessage().contains("offset+limit exceeds"));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.integer(Map.of("offset", Long.MAX_VALUE), "offset", 0, 0, VTSupport.MAX_PAGE_WINDOW - 1));
        assertThrows(IllegalArgumentException.class, () -> VTSupport.integer(Map.of("limit", 1.5), "limit", 100, 1, VTSupport.MAX_LIMIT));
        assertEquals(3, VTSupport.integer(Map.of("limit", 3), "limit", 100, 1, VTSupport.MAX_LIMIT));
        assertNotEquals(new VTSupport.MatchQueryKey(0.9, 1, 1, "1000", "2000", 0),
            new VTSupport.MatchQueryKey(0.9, 1, 1, "1000", "2000", 1));
    }

    @Test
    void outputSchemaIsDeclaredOnlyForVtMatches() {
        assertNotNull(new VTTool("vt_matches").getOutputSchema());
        assertEquals("object", new VTTool("vt_matches").getOutputSchema().get("type"));
        for (String name : List.of("vt_sessions", "vt_session", "vt_correlators", "vt_correlate",
                "vt_review_matches", "vt_add_matches", "vt_markup", "vt_apply_markup", "vt_unapply_markup")) {
            assertNull(new VTTool(name).getOutputSchema(), name);
        }
    }
}
