/*
 * MCP tool that lists functions with optional pattern filtering and pagination.
 * Consolidates list_functions and search_functions functionality.
 */
package ghidrassistmcp.tools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidrassistmcp.McpTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists functions with optional pattern filtering and pagination.
 * Supports substring, wildcard/glob, regex, starts_with, and ends_with matching.
 */
public class ListFunctionsTool implements McpTool {

    @Override
    public boolean isCacheable() {
        return true;
    }

    @Override
    public String getName() {
        return "get_functions";
    }

    @Override
    public String getDescription() {
        return "List functions with optional pattern filtering (supports substring, wildcard/glob, regex) and pagination";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object",
            Map.ofEntries(
                Map.entry("pattern", Map.of(
                    "type", "string",
                    "description", "Optional filter pattern. Behavior depends on match_mode."
                )),
                Map.entry("match_mode", Map.of(
                    "type", "string",
                    "description", "How to interpret the pattern. " +
                        "'auto' (default): uses glob if pattern contains * or ?, otherwise substring. " +
                        "'contains': substring match. " +
                        "'wildcard': glob pattern (* = any chars, ? = single char). " +
                        "'regex': full Java regex. " +
                        "'starts_with': prefix match. " +
                        "'ends_with': suffix match.",
                    "enum", List.of("auto", "contains", "wildcard", "regex", "starts_with", "ends_with"),
                    "default", "auto"
                )),
                Map.entry("case_sensitive", Map.of(
                    "type", "boolean",
                    "description", "Whether matching is case-sensitive (default true)",
                    "default", true
                )),
                Map.entry("offset", Map.of(
                    "type", "integer",
                    "description", "Number of matching results to skip (default 0)",
                    "default", 0
                )),
                Map.entry("limit", Map.of(
                    "type", "integer",
                    "description", "Maximum number of results to return (default 100)",
                    "default", 100
                ))
            ),
            List.of(), null, null, null);
    }

    /**
     * Convert a glob pattern to a compiled regex Pattern.
     * Supports * (any chars) and ? (single char). All other regex metacharacters are escaped.
     */
    private static Pattern globToRegex(String glob, boolean caseSensitive) {
        StringBuilder regex = new StringBuilder("^");
        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*':
                    regex.append(".*");
                    break;
                case '?':
                    regex.append('.');
                    break;
                // Escape regex metacharacters
                case '.': case '(': case ')': case '[': case ']':
                case '{': case '}': case '\\': case '^': case '$':
                case '|': case '+':
                    regex.append('\\').append(c);
                    break;
                default:
                    regex.append(c);
                    break;
            }
        }
        regex.append('$');
        int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
        return Pattern.compile(regex.toString(), flags);
    }

    /**
     * Create a Predicate that tests function names according to the resolved match mode.
     * Returns the predicate and the effective mode name (for display in the header).
     */
    private static MatcherResult createMatcher(String pattern, String matchMode, boolean caseSensitive) {
        // Resolve "auto" mode
        String effectiveMode = matchMode;
        if ("auto".equals(matchMode)) {
            if (pattern.indexOf('*') >= 0 || pattern.indexOf('?') >= 0) {
                effectiveMode = "wildcard";
            } else {
                effectiveMode = "contains";
            }
        }

        Predicate<String> predicate;
        switch (effectiveMode) {
            case "wildcard": {
                Pattern compiled = globToRegex(pattern, caseSensitive);
                predicate = name -> compiled.matcher(name).matches();
                break;
            }
            case "regex": {
                int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                Pattern compiled = Pattern.compile(pattern, flags);
                predicate = name -> compiled.matcher(name).matches();
                break;
            }
            case "starts_with": {
                String p = caseSensitive ? pattern : pattern.toLowerCase(Locale.ROOT);
                predicate = name -> {
                    String n = caseSensitive ? name : name.toLowerCase(Locale.ROOT);
                    return n.startsWith(p);
                };
                break;
            }
            case "ends_with": {
                String p = caseSensitive ? pattern : pattern.toLowerCase(Locale.ROOT);
                predicate = name -> {
                    String n = caseSensitive ? name : name.toLowerCase(Locale.ROOT);
                    return n.endsWith(p);
                };
                break;
            }
            case "contains":
            default: {
                String p = caseSensitive ? pattern : pattern.toLowerCase(Locale.ROOT);
                predicate = name -> {
                    String n = caseSensitive ? name : name.toLowerCase(Locale.ROOT);
                    return n.contains(p);
                };
                break;
            }
        }
        return new MatcherResult(predicate, effectiveMode);
    }

    /** Simple holder for a predicate and the effective mode label. */
    private static class MatcherResult {
        final Predicate<String> predicate;
        final String effectiveMode;
        MatcherResult(Predicate<String> predicate, String effectiveMode) {
            this.predicate = predicate;
            this.effectiveMode = effectiveMode;
        }
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        if (currentProgram == null) {
            return McpSchema.CallToolResult.builder()
                .addTextContent("No program currently loaded")
                .build();
        }

        // Parse optional parameters
        String pattern = (String) arguments.get("pattern");
        boolean caseSensitive = true;
        if (arguments.get("case_sensitive") instanceof Boolean) {
            caseSensitive = (Boolean) arguments.get("case_sensitive");
        }

        String matchMode = "auto";
        if (arguments.get("match_mode") instanceof String) {
            matchMode = (String) arguments.get("match_mode");
        }

        int offset = 0;
        int limit = 100;  // Default limit

        if (arguments.get("offset") instanceof Number) {
            offset = ((Number) arguments.get("offset")).intValue();
        }
        if (arguments.get("limit") instanceof Number) {
            limit = ((Number) arguments.get("limit")).intValue();
        }

        try {
            String result = listFunctions(currentProgram, pattern, matchMode, caseSensitive, offset, limit);
            return McpSchema.CallToolResult.builder()
                .addTextContent(result)
                .build();
        } catch (PatternSyntaxException e) {
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Invalid regex pattern: " + e.getMessage() +
                    "\n\nHint: If you meant to use wildcards like * and ?, try match_mode: \"wildcard\" instead of \"regex\".")
                .build();
        }
    }

    private String listFunctions(Program program, String pattern, String matchMode,
                                  boolean caseSensitive, int offset, int limit) {
        StringBuilder result = new StringBuilder();

        boolean hasPattern = pattern != null && !pattern.trim().isEmpty();

        Predicate<String> matcher = null;
        String effectiveMode = null;

        if (hasPattern) {
            MatcherResult mr = createMatcher(pattern, matchMode, caseSensitive);
            matcher = mr.predicate;
            effectiveMode = mr.effectiveMode;

            result.append("Functions matching pattern: \"").append(pattern).append("\"");
            result.append(" [mode: ").append(effectiveMode);
            result.append(", case ").append(caseSensitive ? "sensitive" : "insensitive").append("]\n\n");
        } else {
            result.append("Functions in program:\n\n");
        }

        FunctionIterator functions = program.getFunctionManager().getFunctions(true);

        // Collect matching functions
        List<Function> matchingFunctions = new ArrayList<>();
        while (functions.hasNext()) {
            Function function = functions.next();

            if (hasPattern) {
                if (matcher.test(function.getName()) || matcher.test(function.getName(true))) {
                    matchingFunctions.add(function);
                }
            } else {
                matchingFunctions.add(function);
            }
        }

        int totalCount = matchingFunctions.size();
        int count = 0;

        // Apply offset and limit
        for (int i = offset; i < matchingFunctions.size() && count < limit; i++) {
            Function function = matchingFunctions.get(i);
            result.append("- ").append(function.getName(true))
                  .append(" @ ").append(function.getEntryPoint())
                  .append(" (").append(function.getParameterCount()).append(" params)")
                  .append("\n");
            count++;
        }

        if (totalCount == 0) {
            if (hasPattern) {
                result.append("No functions found matching pattern: \"").append(pattern).append("\"");
            } else {
                result.append("No functions found in the program.");
            }
        } else {
            result.append("\nShowing ").append(count).append(" of ").append(totalCount);
            result.append(hasPattern ? " matching functions" : " functions");
            if (offset > 0) {
                result.append(" (offset: ").append(offset).append(")");
            }
        }

        return result.toString();
    }
}
