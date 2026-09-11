package ghidrassistmcp.tools;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import org.junit.jupiter.api.Test;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;

/** Verifies shared-repository API dispatch without contacting a real repository. */
class ProjectRepositoryContractTest {
    private final Map<String, Object> state = new HashMap<>(Map.of(
        "getPathname", "/fixture", "getFileID", "test", "canCheckout", true,
        "canCheckin", true, "canAddToRepository", true));
    private final List<String> mutations = new ArrayList<>();
    private CheckinHandler checkinHandler;
    private boolean undoKeptCopy;
    private boolean exclusive;
    private final DomainFile file = proxy(DomainFile.class, (name, args) -> {
        switch (name) {
            case "checkout" -> {
                mutations.add(name);
                exclusive = (Boolean) args[0];
                state.put("isCheckedOut", true);
                state.put("isCheckedOutExclusive", exclusive);
                return true;
            }
            case "checkin" -> { mutations.add(name); checkinHandler = (CheckinHandler) args[0]; }
            case "undoCheckout" -> { mutations.add(name); undoKeptCopy = (Boolean) args[0]; }
            case "addToVersionControl" -> mutations.add(name);
        }
        return state.get(name);
    });
    private final DomainFolder root = proxy(DomainFolder.class,
        (name, args) -> name.equals("getFile") && args[0].equals("fixture") ? file : null);
    private final ProjectData data = proxy(ProjectData.class,
        (name, args) -> name.equals("getRootFolder") ? root : null);
    private final Project project = proxy(Project.class,
        (name, args) -> name.equals("getProjectData") ? data : null);
    private final ProjectRepositoryTool tool = new ProjectRepositoryTool(() -> project);

    @Test void readOperationsNeverMutateAndHandleAbsentHistory() {
        for (String action : List.of("status", "history", "checkouts")) {
            var result = tool.execute(Map.of("action", action, "path", "/fixture"), null);
            assertFalse(Boolean.TRUE.equals(result.isError()), result.content().toString());
        }
        assertTrue(mutations.isEmpty());
    }

    @Test void checkoutUsesRequestedExclusivityAndRejectsUpgrade() {
        assertFalse(Boolean.TRUE.equals(tool.execute(Map.of("action", "checkout", "path", "/fixture"), null).isError()));
        assertFalse(exclusive);
        assertTrue(tool.execute(Map.of("action", "checkout", "path", "/fixture", "exclusive", true), null).isError());
        assertEquals(List.of("checkout"), mutations);
    }

    @Test void checkinRequiresCommentAndRefusesMergeBeforeInvokingApi() throws Exception {
        assertTrue(tool.execute(Map.of("action", "checkin", "path", "/fixture"), null).isError());
        state.put("canMerge", true);
        assertTrue(tool.execute(Map.of("action", "checkin", "path", "/fixture", "comment", "test"), null).isError());
        assertTrue(mutations.isEmpty());
        state.put("canMerge", false);
        assertFalse(Boolean.TRUE.equals(tool.execute(Map.of("action", "checkin", "path", "/fixture", "comment", "test"), null).isError()));
        assertEquals("test", checkinHandler.getComment());
        assertTrue(checkinHandler.keepCheckedOut());
        assertTrue(checkinHandler.createKeepFile());
    }

    @Test void undoRequiresExplicitConfirmationAndAlwaysKeepsCopy() {
        state.put("isCheckedOut", true);
        assertTrue(tool.execute(Map.of("action", "undo_checkout", "path", "/fixture"), null).isError());
        assertTrue(mutations.isEmpty());
        assertFalse(Boolean.TRUE.equals(tool.execute(Map.of("action", "undo_checkout", "path", "/fixture", "confirm", true), null).isError()));
        assertTrue(undoKeptCopy);
    }

    @Test void dirtyOrBusyFilesPreventEveryMutation() {
        for (String condition : List.of("isChanged", "isBusy")) {
            state.put(condition, true);
            for (String action : List.of("checkout", "checkin", "add", "undo_checkout")) {
                assertTrue(tool.execute(Map.of("action", action, "path", "/fixture", "comment", "test", "confirm", true), null).isError());
            }
            state.put(condition, false);
        }
        assertTrue(mutations.isEmpty());
    }

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, BiFunction<String, Object[], Object> handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, method, args) -> {
            Object value = handler.apply(method.getName(), args);
            if (value != null) return value;
            if (method.getReturnType() == boolean.class) return false;
            if (method.getReturnType() == int.class) return 0;
            if (method.getReturnType() == long.class) return 0L;
            return null;
        });
    }
}
