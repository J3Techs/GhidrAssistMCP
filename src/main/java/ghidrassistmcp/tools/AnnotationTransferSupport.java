package ghidrassistmcp.tools;

/** Pure policy helpers shared by annotation transfer and regression tests. */
final class AnnotationTransferSupport {
    enum Conflict { PRESERVE, REPLACE, ERROR }
    enum Decision { APPLY, PRESERVE, CONFLICT }

    private AnnotationTransferSupport() { }

    static boolean previewByDefault(boolean hasAnnotations, Boolean requestedPreview, boolean dryRun) {
        if (dryRun || !hasAnnotations) return true;
        return requestedPreview == null || requestedPreview;
    }

    static Decision decide(boolean exists, boolean same, Conflict policy) {
        if (!exists || same) return Decision.APPLY;
        return switch (policy) {
            case PRESERVE -> Decision.PRESERVE;
            case REPLACE -> Decision.APPLY;
            case ERROR -> Decision.CONFLICT;
        };
    }

    static Conflict parsePolicy(String value) {
        if (value == null || value.isBlank() || "preserve".equalsIgnoreCase(value)) return Conflict.PRESERVE;
        if ("replace".equalsIgnoreCase(value)) return Conflict.REPLACE;
        if ("error".equalsIgnoreCase(value)) return Conflict.ERROR;
        throw new IllegalArgumentException("conflict_policy must be preserve, replace, or error");
    }
}
