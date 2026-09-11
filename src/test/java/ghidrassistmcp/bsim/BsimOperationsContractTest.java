package ghidrassistmcp.bsim;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

class BsimOperationsContractTest {
    @Test
    void queryOperationsExposeBoundedReadOnlyContract() {
        var operations = BsimQueryOperations.operations();
        var names = operations.stream().map(BsimOperation::name).collect(Collectors.toSet());
        assertTrue(names.containsAll(Set.of("list_executables", "list_functions", "get_function",
            "query_vectors", "compare_functions", "query_functions", "query_program",
            "overview", "match_programs")));
        assertTrue(operations.stream().filter(op -> !op.name().equals("match_programs"))
            .allMatch(BsimOperation::readOnly));
        assertTrue(operations.stream().allMatch(op -> op.properties() != null && op.required() != null));
        var vectors = operations.stream().filter(op -> op.name().equals("query_vectors")).findFirst().orElseThrow();
        assertEquals("array", ((Map<?, ?>) vectors.properties().get("vector_ids")).get("type"));
        assertEquals("string", ((Map<?, ?>) ((Map<?, ?>) vectors.properties().get("vector_ids")).get("items")).get("type"));
    }

    @Test
    void matchOperationsSeparatePreviewFromConfirmedMutation() {
        var operations = BsimMatchOperations.operations();
        var preview = operations.stream().filter(op -> op.name().equals("preview_matches")).findFirst().orElseThrow();
        var apply = operations.stream().filter(op -> op.name().equals("apply_matches")).findFirst().orElseThrow();
        assertTrue(preview.readOnly());
        assertFalse(apply.readOnly());
        assertTrue(apply.destructive());
        assertEquals(java.util.List.of("preview_id", "selected", "confirm"), apply.required());
        assertTrue(apply.properties().get("preview_id") instanceof Map<?, ?>);
        assertTrue(apply.properties().get("selected") instanceof Map<?, ?>);
    }
}
