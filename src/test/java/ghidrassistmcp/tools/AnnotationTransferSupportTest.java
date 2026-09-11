package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AnnotationTransferSupportTest {
    @Test
    void annotationsPreviewByDefaultAndDryRunAlwaysWins() {
        assertTrue(AnnotationTransferSupport.previewByDefault(true, null, false));
        assertTrue(AnnotationTransferSupport.previewByDefault(true, true, false));
        assertFalse(AnnotationTransferSupport.previewByDefault(true, false, false));
        assertTrue(AnnotationTransferSupport.previewByDefault(true, false, true));
        assertTrue(AnnotationTransferSupport.previewByDefault(false, false, false));
    }

    @Test
    void policiesPreserveReplaceOrFailOnlyOnActualConflict() {
        for (AnnotationTransferSupport.Conflict policy : AnnotationTransferSupport.Conflict.values()) {
            assertEquals(AnnotationTransferSupport.Decision.APPLY,
                AnnotationTransferSupport.decide(false, false, policy));
            assertEquals(AnnotationTransferSupport.Decision.APPLY,
                AnnotationTransferSupport.decide(true, true, policy));
        }
        assertEquals(AnnotationTransferSupport.Decision.PRESERVE,
            AnnotationTransferSupport.decide(true, false, AnnotationTransferSupport.Conflict.PRESERVE));
        assertEquals(AnnotationTransferSupport.Decision.APPLY,
            AnnotationTransferSupport.decide(true, false, AnnotationTransferSupport.Conflict.REPLACE));
        assertEquals(AnnotationTransferSupport.Decision.CONFLICT,
            AnnotationTransferSupport.decide(true, false, AnnotationTransferSupport.Conflict.ERROR));
    }

    @Test
    void policyParsingIsExplicit() {
        assertEquals(AnnotationTransferSupport.Conflict.PRESERVE,
            AnnotationTransferSupport.parsePolicy(null));
        assertEquals(AnnotationTransferSupport.Conflict.REPLACE,
            AnnotationTransferSupport.parsePolicy("REPLACE"));
        assertEquals(AnnotationTransferSupport.Conflict.ERROR,
            AnnotationTransferSupport.parsePolicy("error"));
        assertThrows(IllegalArgumentException.class,
            () -> AnnotationTransferSupport.parsePolicy("merge"));
    }
}
