package ghidrassistmcp.tools;

/** Bounds text while it is built and always labels omitted evidence. */
final class BoundedQueryText {
    static final int MAX_CHARS = 200_000;
    private static final String NOTICE = "\n[TRUNCATED: query output budget reached; narrow the query or request another page.]\n";
    private final StringBuilder text = new StringBuilder();
    private final int maximum;
    private boolean truncated;
    BoundedQueryText() { this(MAX_CHARS); }
    BoundedQueryText(int maximum) { this.maximum = maximum; }
    BoundedQueryText append(Object value) {
        if (truncated) return this;
        String addition = String.valueOf(value);
        int available = Math.max(0, maximum - NOTICE.length() - text.length());
        if (addition.length() > available) {
            int end = available;
            if (end > 0 && Character.isHighSurrogate(addition.charAt(end - 1))) end--;
            text.append(addition, 0, end);
            truncated = true;
        } else if (!truncated) text.append(addition);
        return this;
    }
    boolean full() { return truncated; }
    void truncate() { truncated = true; }
    @Override public String toString() { return text + (truncated ? NOTICE : ""); }
}
