package ghidrassistmcp;

import java.util.*;
import ghidra.program.model.listing.Program;

/** Exact selectors shared by dispatch and diagnostics; display names must be unique. */
public final class ProgramIdentity {
    private ProgramIdentity() {}

    /** Allows resource handlers to distinguish an absent target from an invalid selector. */
    public static final class NotOpenException extends IllegalArgumentException {
        public NotOpenException(String selector) { super("Program not open: " + selector); }
    }

    public static String id(Program program) {
        var file = program.getDomainFile();
        if (file == null) return "unsaved:" + program.getName() + ":" + Integer.toUnsignedString(System.identityHashCode(program));
        var url = file.getLocalProjectURL(null);
        if (url == null) url = file.getSharedProjectURL(null);
        String origin = url == null ? Objects.toString(file.getProjectLocator(), "transient:" + Integer.toUnsignedString(System.identityHashCode(program)))
            + file.getPathname() + "#file=" + file.getFileID() : url.toString();
        return origin + "#version=" + file.getVersion();
    }

    public static Map<String, Object> describe(Program program) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("program_id", id(program)); result.put("name", program.getName());
        result.put("modification_number", Long.toString(program.getModificationNumber()));
        result.put("dirty", program.isChanged()); result.put("changeable", program.isChangeable());
        result.put("transaction_active", program.getCurrentTransactionInfo() != null);
        var file = program.getDomainFile();
        if (file != null) {
            result.put("path", file.getPathname()); result.put("file_id", file.getFileID());
            result.put("version", file.getVersion()); result.put("read_only", file.isReadOnly());
            result.put("can_save", file.canSave()); result.put("busy", file.isBusy());
            var url = file.getLocalProjectURL(null);
            if (url == null) url = file.getSharedProjectURL(null);
            if (url != null) result.put("program_url", url.toString());
        }
        return result;
    }

    public static Program resolve(String selector, Collection<Program> programs) {
        if (selector == null || selector.isBlank()) throw new IllegalArgumentException("Program selector must be nonblank");
        List<Program> matches = programs.stream().filter(Objects::nonNull).filter(p -> !p.isClosed())
            .distinct().filter(p -> matches(selector, p)).toList();
        if (matches.isEmpty()) throw new NotOpenException(selector);
        if (matches.size() > 1) throw new IllegalArgumentException("Ambiguous program selector; use program_id: " + selector);
        return matches.get(0);
    }

    private static boolean matches(String selector, Program p) {
        if (selector.equals(p.getName()) || selector.equals(id(p))) return true;
        var file = p.getDomainFile();
        return file != null && (selector.equals(file.getPathname())
            || file.getLocalProjectURL(null) != null && selector.equals(file.getLocalProjectURL(null).toString())
            || file.getSharedProjectURL(null) != null && selector.equals(file.getSharedProjectURL(null).toString()));
    }
}
