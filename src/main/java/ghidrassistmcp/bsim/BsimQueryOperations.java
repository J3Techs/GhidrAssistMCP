package ghidrassistmcp.bsim;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryExeInfo;
import ghidra.features.bsim.query.protocol.QueryName;
import ghidra.features.bsim.query.protocol.ResponseExe;
import ghidra.features.bsim.query.protocol.ResponseName;
import ghidra.features.bsim.query.facade.SFOverviewInfo;
import ghidra.features.bsim.query.facade.SFQueryInfo;
import ghidra.features.bsim.query.facade.SimilarFunctionQueryService;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.features.bsim.query.protocol.ResponseNearestVector;
import ghidra.features.bsim.query.protocol.QueryVectorMatch;
import ghidra.features.bsim.query.protocol.ResponseVectorMatch;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import generic.lsh.vector.VectorCompare;

/** Read-only operations over a stock Ghidra BSim database and source programs. */
public final class BsimQueryOperations {
    private static final int DEFAULT_LIMIT = 100;
    private static final int MAX_LIMIT = 1000;

    private BsimQueryOperations() {
    }

    public static List<BsimOperation> operations() {
        Map<String, Object> page = Map.of("limit", field("integer", 1, 1000), "offset", field("integer", 0, 100000),
            "md5", field("string", null, null), "executable", field("string", null, null),
            "architecture", field("string", null, null), "compiler", field("string", null, null), "include_generated", field("boolean", null, null));
        return List.of(
            BsimOperation.of("list_executables", "List bounded BSim executable records.", page,
                List.of(), true, false, false, BsimQueryOperations::listExecutables),
            BsimOperation.of("list_functions", "List bounded functions in the BSim database.",
                Map.of("md5", field("string", null, null), "executable", field("string", null, null),
                    "function", field("string", null, null), "limit", field("integer", 1, 1000), "offset", field("integer", 0, 100000)),
                List.of(), true, false, false, BsimQueryOperations::listFunctions),
            BsimOperation.of("get_function", "Resolve one function by executable and name.",
                Map.of("executable", field("string", null, null), "md5", field("string", null, null), "function", field("string", null, null), "address", field("string", null, null)),
                List.of("function"), true, false, false, BsimQueryOperations::getFunction),
            BsimOperation.of("query_vectors", "Query similar functions using stock BSim vectors.",
                Map.of("addresses", arrayField("string"), "vector_ids", arrayField("string"), "similarity", field("number", 0, 1),
                    "significance", field("number", 0, null), "limit", field("integer", 1, 1000)), List.of(), true, false, true,
                BsimQueryOperations::queryVectors),
            BsimOperation.of("compare_functions", "Compare selected functions through stock BSim.",
                Map.of("left", field("string", null, null), "right", field("string", null, null), "program", field("string", null, null)), List.of("left", "right"), true, false,
                false, BsimQueryOperations::compareFunctions),
            BsimOperation.of("overview", "Return bounded BSim overview counts for source functions.",
                similaritySchema(), List.of(), true, false, true,
                BsimQueryOperations::overview),
            BsimOperation.of("query_program", "Find similar database functions for every function in selected programs.",
                similaritySchema(), List.of(), true, false, true, BsimQueryOperations::queryProgram),
            BsimOperation.of("query_functions", "Query bounded BSim source functions.",
                similaritySchema(), List.of("addresses"),
                true, false, true, BsimQueryOperations::queryProgram),
            BsimOperation.of("match_programs", "Prepare a bounded program match query.",
                Map.of("programs", arrayField("string"), "similarity", field("number", 0, 1), "significance", field("number", 0, null), "max_functions", field("integer", 1, 10000), "limit", field("integer", 1, 1000)),
                List.of("programs"), true, false, true, BsimQueryOperations::matchPrograms));
    }

    private static Map<String, Object> similaritySchema() {
        return Map.of("program", field("string", null, null), "addresses", arrayField("string"),
            "similarity", field("number", 0, 1), "significance", field("number", 0, null),
            "limit", field("integer", 1, 1000), "batch_size", field("integer", 1, 100),
            "exclude_self", field("boolean", null, null), "filters", Map.of("type", "array", "items", Map.of("type", "object", "properties", Map.of("type", field("string", null, null), "value", field("string", null, null)), "required", List.of("type", "value"))));
    }

    private static Map<String, Object> field(String type, Number minimum, Number maximum) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("type", type);
        if (minimum != null) value.put("minimum", minimum);
        if (maximum != null) value.put("maximum", maximum);
        return value;
    }

    private static Map<String, Object> arrayField(String itemType) {
        Map<String, Object> value = field("array", null, null);
        value.put("items", Map.of("type", itemType));
        return value;
    }

    private static Map<String, Object> listExecutables(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        int limit = limit(args);
        int offset = BsimSupport.integer(args, "offset", 0, 100000);
        try (FunctionDatabase database = context.database(args)) {
            QueryExeInfo query = new QueryExeInfo();
            query.limit = offset + limit + 1;
            query.filterMd5 = BsimSupport.text(args, "md5", null);
            query.filterExeName = BsimSupport.text(args, "executable", null);
            query.filterArch = BsimSupport.text(args, "architecture", null);
            query.filterCompilerName = BsimSupport.text(args, "compiler", null);
            query.includeFakes = BsimSupport.bool(args, "include_generated", true);
            ResponseExe response = BsimSupport.query(database, query);
            List<Map<String, Object>> records = new ArrayList<>();
            for (ExecutableRecord record : response.records.stream().skip(offset).toList()) {
                monitor.checkCancelled();
                records.add(executable(record));
                if (records.size() >= limit) break;
            }
            return result(records, response.records.size() > offset + limit);
        }
    }

    private static Map<String, Object> listFunctions(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        List<Map<String, Object>> rows = new ArrayList<>();
        int limit = limit(args);
        int offset = BsimSupport.integer(args, "offset", 0, 100000);
        if (!args.containsKey("md5") && !args.containsKey("executable")) throw new IllegalArgumentException("Specify md5 or executable; enumerate databases with list_executables");
        try (FunctionDatabase database = context.database(args)) {
            QueryName query = new QueryName();
            query.spec.exemd5 = args.get("md5") instanceof String s ? s : null;
            query.spec.exename = args.get("executable") instanceof String s ? s : null;
            query.funcname = args.get("function") instanceof String s ? s : "";
            query.maxfunc = offset + limit + 1;
            query.fillinSigs = false;
            ResponseName response = BsimSupport.query(database, query);
            var iterator = response.manage.listAllFunctions();
            for (int i = 0; i < offset && iterator.hasNext(); i++) iterator.next();
            while (iterator.hasNext() && rows.size() < limit) {
                monitor.checkCancelled();
                rows.add(description(iterator.next()));
            }
            return result(rows, iterator.hasNext());
        }
    }

    private static Map<String, Object> getFunction(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        String requestedName = BsimSupport.text(args, "function");
        try (FunctionDatabase database = context.database(args)) {
            QueryName query = new QueryName();
            query.spec.exemd5 = args.get("md5") instanceof String s ? s : null;
            query.spec.exename = args.get("executable") instanceof String s ? s : null;
            query.funcname = requestedName;
            if (!args.containsKey("md5") && !args.containsKey("executable")) throw new IllegalArgumentException("Specify md5 or executable");
            query.maxfunc = 100001;
            query.fillinSigs = true;
            ResponseName response = BsimSupport.query(database, query);
            var iterator = response.manage.listAllFunctions();
            FunctionDescription found = null;
            String address = BsimSupport.text(args, "address", null);
            while (iterator.hasNext()) {
                var next = iterator.next();
                if (address != null && Long.parseUnsignedLong(address.replaceFirst("^0[xX]", ""), 16) != next.getAddress()) continue;
                if (found != null) throw new IllegalArgumentException("Ambiguous function name; supply exact executable MD5 and hex address");
                found = next;
            }
            if (found != null) return description(found);
            throw new IllegalArgumentException("function not found: " + requestedName);
        }
    }

    private static Map<String, Object> queryProgram(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        return runSimilarity(context, args, monitor, false);
    }

    private static Map<String, Object> queryVectors(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        if (args.get("vector_ids") instanceof List<?> ids && !ids.isEmpty()) {
            int limit = limit(args);
            try (FunctionDatabase database = context.database(args)) {
                QueryVectorMatch query = new QueryVectorMatch();
                query.max = limit;
                for (Object id : ids) {
                    try {
                        String value = id instanceof String s ? s : id.toString();
                        query.vectorIds.add(value.startsWith("0x") ? Long.parseUnsignedLong(value.substring(2), 16) : Long.parseUnsignedLong(value));
                    } catch (RuntimeException e) { throw new IllegalArgumentException("vector_ids must be unsigned decimal or 0x-prefixed strings"); }
                }
                ResponseVectorMatch response = BsimSupport.query(database, query);
                List<Map<String, Object>> rows = new ArrayList<>();
                var iterator = response.manage.listAllFunctions();
                while (iterator.hasNext() && rows.size() < limit) rows.add(description(iterator.next()));
                return result(rows, rows.size() >= limit);
            }
        }
        return runSimilarity(context, args, monitor, false);
    }

    private static Map<String, Object> matchPrograms(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        int limit = limit(args);
        int maximumFunctions = Math.max(1, BsimSupport.integer(args, "max_functions", 1000, 10000));
        double threshold = BsimSupport.decimal(args, "similarity", 0.7, 0.0, 1.0);
        double significance = BsimSupport.decimal(args, "significance", 0, 0, Double.MAX_VALUE);
        var handles = context.resolvePrograms(args, monitor);
        if (handles.size() != 2) throw new IllegalArgumentException("Specify exactly two programs");
        List<Map<String, Object>> rows = new ArrayList<>();
        try (var leftHandle = handles.get(0); var rightHandle = handles.get(1)) {
            Program leftProgram = leftHandle.program(), rightProgram = rightHandle.program();
            var vectors = weights(leftProgram, rightProgram);
            var left = boundedFunctions(leftProgram, maximumFunctions + 1, monitor);
            var right = boundedFunctions(rightProgram, maximumFunctions + 1, monitor);
            if (left.size() > maximumFunctions || right.size() > maximumFunctions)
                throw new IllegalArgumentException("Program exceeds max_functions; increase the explicit bound or query a database corpus");
            List<Signature> rightVectors = new ArrayList<>();
            for (Function function : right) rightVectors.add(signature(rightProgram, function, vectors, monitor));
            for (Function leftFunction : left) {
                String unit = "match:" + leftHandle.identity() + ":" + leftFunction.getEntryPoint();
                var completed = context.completed(unit);
                if (completed != null) {
                    @SuppressWarnings("unchecked") var saved = (List<Map<String, Object>>) completed.get("results");
                    rows.addAll(saved); continue;
                }
                var leftVector = signature(leftProgram, leftFunction, vectors, monitor);
                List<Map<String, Object>> candidates = new ArrayList<>();
                for (int i = 0; i < right.size(); i++) {
                    monitor.checkCancelled();
                    VectorCompare compare = new VectorCompare();
                    double similarity = leftVector.first.compare(rightVectors.get(i).first, compare);
                    double score = vectors.calculateSignificance(compare);
                    if (similarity >= threshold && score >= significance) {
                        var row = new LinkedHashMap<String, Object>();
                        row.put("program", leftHandle.identity()); row.put("address", leftFunction.getEntryPoint().toString());
                        row.put("source_program", rightHandle.identity()); row.put("source_address", right.get(i).getEntryPoint().toString());
                        row.put("name", right.get(i).getName()); row.put("similarity", similarity); row.put("significance", score);
                        candidates.add(row);
                    }
                }
                candidates.sort(java.util.Comparator.comparingDouble((Map<String, Object> row) -> ((Number) row.get("similarity")).doubleValue()).reversed());
                var best = new ArrayList<>(candidates.subList(0, Math.min(limit, candidates.size())));
                context.checkpoint(unit, Map.of("results", best)); rows.addAll(best);
            }
        }
        return result(rows, false);
    }

    private static List<Function> boundedFunctions(Program program, int limit, TaskMonitor monitor) throws Exception {
        List<Function> functions = new ArrayList<>();
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (functions.size() >= limit) break;
            functions.add(function);
        }
        return functions;
    }

    private static Signature signature(Program program, Function function, TaskMonitor monitor) throws Exception {
        return signature(program, function, weights(program, program), monitor);
    }

    private static generic.lsh.vector.LSHVectorFactory weights(Program left, Program right) throws Exception {
        var vectors = new generic.lsh.vector.WeightedLSHCosineVectorFactory();
        var file = GenSignatures.getWeightsFile(left.getLanguageID(), right.getLanguageID());
        try (var stream = file.getInputStream()) {
            var parser = new ghidra.xml.NonThreadedXmlPullParserImpl(stream, "BSim weights", ghidra.util.xml.SpecXmlUtils.getXmlHandler(), false);
            try { vectors.readWeights(parser); } finally { parser.dispose(); }
        }
        return vectors;
    }

    private static Signature signature(Program program, Function function, generic.lsh.vector.LSHVectorFactory vectors, TaskMonitor monitor) throws Exception {
        var decompiler = new ghidra.app.decompiler.DecompInterface();
        try {
            monitor.checkCancelled();
            decompiler.setOptions(new ghidra.app.decompiler.DecompileOptions());
            decompiler.setSignatureSettings(vectors.getSettings());
            if (!decompiler.openProgram(program)) throw new IllegalStateException(decompiler.getLastMessage());
            var signature = decompiler.generateSignatures(function, false, 30, monitor);
            monitor.checkCancelled();
            if (signature == null || signature.features == null || signature.features.length == 0)
                throw new IllegalStateException("No BSim features for " + function.getEntryPoint());
            return new Signature(vectors.buildVector(signature.features), vectors);
        }
        finally { decompiler.dispose(); }
    }

    private record Signature(generic.lsh.vector.LSHVector first, generic.lsh.vector.LSHVectorFactory second) {}

    private static Map<String, Object> compareFunctions(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        List<BsimContext.ProgramHandle> handles = context.resolvePrograms(args, monitor);
        if (handles.isEmpty()) throw new IllegalArgumentException("no source program");
        try (BsimContext.ProgramHandle handle = handles.get(0)) {
            Program program = handle.program();
            Function left = functionAt(program, BsimSupport.text(args, "left"));
            Function right = functionAt(program, BsimSupport.text(args, "right"));
                var vectors = weights(program, program);
                var leftVector = signature(program, left, vectors, monitor).first;
                var rightVector = signature(program, right, vectors, monitor).first;
                VectorCompare compare = new VectorCompare();
                double similarity = leftVector.compare(rightVector, compare);
                return Map.of("left", left.getName(), "right", right.getName(), "similarity", similarity,
                    "significance", vectors.calculateSignificance(compare), "settings", vectors.getSettings());
        }
    }

    private static Map<String, Object> overview(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        return runSimilarity(context, args, monitor, true);
    }

    private static Map<String, Object> runSimilarity(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor, boolean overview) throws Exception {
        int limit = limit(args);
        int batchSize = Math.max(1, BsimSupport.integer(args, "batch_size", 20, 100));
        double similarity = BsimSupport.decimal(args, "similarity", 0.7, 0.0, 1.0);
        double significance = BsimSupport.decimal(args, "significance", 0.0, 0.0, Double.MAX_VALUE);
        List<Map<String, Object>> rows = new ArrayList<>();
        int sourceCount = 0;
        for (BsimContext.ProgramHandle handle : context.resolvePrograms(args, monitor)) {
            try (handle) {
                Program program = handle.program();
                List<ghidra.program.database.symbol.FunctionSymbol> symbols = new ArrayList<>(resolveSymbols(program, args, monitor));
                sourceCount += symbols.size();
                if (symbols.isEmpty()) continue;
                String databaseUrl;
                ghidra.features.bsim.query.description.DatabaseInformation databaseInfo;
                try (FunctionDatabase database = context.database(args)) {
                    databaseUrl = database.getURLString(); databaseInfo = database.getInfo();
                }
                try (SimilarFunctionQueryService service = new SimilarFunctionQueryService(program)) {
                    service.initializeDatabase(databaseUrl);
                    for (int from = 0; from < symbols.size(); from += batchSize) {
                        monitor.checkCancelled();
                        String unit = "query:" + handle.identity() + ":" + from;
                        Map<String, Object> completed = context.completed(unit);
                        if (completed != null) {
                            @SuppressWarnings("unchecked") var saved = (List<Map<String, Object>>) completed.get("results");
                            rows.addAll(saved); continue;
                        }
                        var batch = new java.util.LinkedHashSet<>(symbols.subList(from, Math.min(symbols.size(), from + batchSize)));
                        List<Map<String, Object>> batchRows = new ArrayList<>();
                        if (overview) {
                            SFOverviewInfo info = new SFOverviewInfo(batch);
                            info.setSimilarityThreshold(similarity); info.setSignificanceThreshold(significance);
                            ResponseNearestVector response = service.overviewSimilarFunctions(info, null, monitor);
                            for (var item : response.result) batchRows.add(Map.of("program", handle.identity(),
                                "address", Long.toHexString(item.getBase().getAddress()),
                                "name", item.getBase().getFunctionName(), "match_count", item.getTotalCount()));
                        } else {
                            SFQueryInfo info = new SFQueryInfo(batch);
                            info.setSimilarityThreshold(similarity); info.setSignificanceThreshold(significance);
                            info.setMaximumResults(limit);
                            var filter = buildFilter(args, databaseInfo);
                            if (BsimSupport.bool(args, "exclude_self", false) && program.getExecutableMD5() != null)
                                filter.addAtom(new ghidra.features.bsim.gui.filters.NotMd5BSimFilterType(), program.getExecutableMD5());
                            info.getBsimFilter().replaceWith(filter);
                            var response = service.querySimilarFunctions(info, null, monitor);
                            for (SimilarityResult item : response.getSimilarityResults()) {
                                for (SimilarityNote note : item) {
                                    var row = new LinkedHashMap<String, Object>();
                                    row.put("source_program", handle.identity());
                                    row.put("source_address", Long.toHexString(item.getBase().getAddress()));
                                    row.put("source_function", item.getBase().getFunctionName());
                                    row.put("match", description(note.getFunctionDescription()));
                                    row.put("similarity", note.getSimilarity()); row.put("significance", note.getSignificance());
                                    batchRows.add(row);
                                }
                            }
                        }
                        context.checkpoint(unit, Map.of("results", batchRows)); rows.addAll(batchRows);
                    }
                }
            }
        }
        var result = result(rows, false);
        result.put("source_functions", sourceCount); result.put("max_matches_per_function", limit);
        return result;
    }

    private static ghidra.features.bsim.query.protocol.BSimFilter buildFilter(Map<String, Object> args,
            ghidra.features.bsim.query.description.DatabaseInformation info) {
        var result = new ghidra.features.bsim.query.protocol.BSimFilter();
        if (!args.containsKey("filters")) return result;
        if (!(args.get("filters") instanceof List<?> filters) || filters.size() > 100) throw new IllegalArgumentException("filters must be an array of at most 100 entries");
        var types = ghidra.features.bsim.gui.filters.BSimFilterType.generateBsimFilters(info, true);
        for (Object entry : filters) {
            if (!(entry instanceof Map<?, ?> filter) || !(filter.get("type") instanceof String typeName) || !(filter.get("value") instanceof String value))
                throw new IllegalArgumentException("Each filter requires type and value strings");
            var candidates = types.stream().filter(t -> !t.isBlank() && (t.toString().equals(typeName) || t.getXmlValue().equals(typeName))).toList();
            if (candidates.size() != 1) throw new IllegalArgumentException("Unknown or ambiguous filter; use a label from database_info.filter_types: " + typeName);
            var type = candidates.get(0);
            if (!type.isValidValue(value)) throw new IllegalArgumentException("Invalid value for filter " + typeName);
            result.addAtom(type, type.normalizeValue(value));
        }
        return result;
    }

    private static java.util.Set<ghidra.program.database.symbol.FunctionSymbol> resolveSymbols(
            Program program, Map<String, Object> args, TaskMonitor monitor) throws Exception {
        java.util.Set<ghidra.program.database.symbol.FunctionSymbol> result =
            new java.util.LinkedHashSet<>();
        Object values = args.get("addresses");
        if (values == null) {
            for (Function function : program.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                if (!function.isExternal() && !function.isThunk()) result.add((ghidra.program.database.symbol.FunctionSymbol) function.getSymbol());
            }
            return result;
        }
        if (!(values instanceof List<?> list)) throw new IllegalArgumentException("addresses must be an array");
        for (Object value : list) {
            monitor.checkCancelled();
            if (!(value instanceof String text)) throw new IllegalArgumentException("addresses must contain strings");
            var address = program.getAddressFactory().getAddress(text);
            if (address == null) throw new IllegalArgumentException("invalid address: " + text);
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function == null) throw new IllegalArgumentException("no function at address: " + text);
            result.add((ghidra.program.database.symbol.FunctionSymbol) function.getSymbol());
        }
        return result;
    }

    private static Function functionAt(Program program, String text) {
        var address = program.getAddressFactory().getAddress(text);
        if (address == null) throw new IllegalArgumentException("invalid address: " + text);
        Function function = program.getFunctionManager().getFunctionAt(address);
        if (function == null) throw new IllegalArgumentException("no function at address: " + text);
        return function;
    }

    private static int limit(Map<String, Object> args) {
        return BsimSupport.integer(args, "limit", DEFAULT_LIMIT, MAX_LIMIT);
    }

    private static Map<String, Object> executable(ExecutableRecord record) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("md5", record.getMd5());
        row.put("name", record.getNameExec());
        row.put("architecture", record.getArchitecture());
        row.put("compiler", record.getNameCompiler());
        row.put("repository", record.getRepository());
        row.put("path", record.getPath());
        row.put("library", record.isLibrary());
        return row;
    }

    private static Map<String, Object> localFunction(Program program, Function function) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("program", program.getName());
        row.put("name", function.getName());
        row.put("entry", function.getEntryPoint().toString());
        row.put("signature", function.getSignature().getPrototypeString());
        row.put("length", function.getBody().getNumAddresses());
        return row;
    }

    private static Map<String, Object> description(FunctionDescription function) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", function.getFunctionName());
        row.put("address", Long.toHexString(function.getAddress()));
        row.put("repository", function.getExecutableRecord().getRepository());
        row.put("path", function.getExecutableRecord().getPath());
        if (function.getVectorId() != 0) row.put("vector_id", Long.toUnsignedString(function.getVectorId()));
        row.put("executable", function.getExecutableRecord().getNameExec());
        row.put("md5", function.getExecutableRecord().getMd5());
        return row;
    }

    private static Map<String, Object> result(List<Map<String, Object>> rows, boolean truncated) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("results", rows);
        result.put("count", rows.size());
        result.put("truncated", truncated);
        return result;
    }
}
