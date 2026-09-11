package ghidrassistmcp.bsim;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.security.MessageDigest;
import java.util.HexFormat;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.protocol.AdjustVectorIndex;
import ghidra.features.bsim.query.protocol.ExeSpecifier;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.QueryDelete;
import ghidra.features.bsim.query.protocol.QueryExeInfo;
import ghidra.features.bsim.query.protocol.QueryName;
import ghidra.features.bsim.query.protocol.QueryResponseRecord;
import ghidra.features.bsim.query.protocol.QueryUpdate;
import ghidra.features.bsim.query.protocol.ResponseDelete;
import ghidra.features.bsim.query.protocol.ResponseExe;
import ghidra.features.bsim.query.protocol.ResponseName;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlPullParser;

/** Stock-API BSim corpus/signature operations.  All paths are artifact-relative. */
public final class BsimCorpusOperations {
    private static final int MAX_FILES = 10000;
    private static final int MAX_RESULTS = 10000;

    private BsimCorpusOperations() {}

    public static List<BsimOperation> operations() {
        return List.of(
            BsimOperation.of("generate_signatures", "Generate staged BSim signature XML from saved analyzed programs.",
                Map.of("output_directory", BsimSupport.stringProperty("Artifact-relative XML directory"),
                    "programs", Map.of("type", "array", "items", Map.of("type", "string")), "database", BsimSupport.stringProperty("Connection profile"),
                    "config", BsimSupport.stringProperty("BSim configuration template"), "metadata_only", Map.of("type", "boolean"), "addresses", Map.of("type", "array", "items", Map.of("type", "string"))),
                List.of("output_directory"), false, false, true, BsimCorpusOperations::generateSignatures),
            BsimOperation.of("ingest", "Insert staged BSim signature XML into a configured database.",
                Map.of("xml_directory", BsimSupport.stringProperty("Artifact-relative XML directory"),
                    "programs", Map.of("type", "array", "items", Map.of("type", "string")), "database", BsimSupport.stringProperty("Connection profile"),
                    "database_url", BsimSupport.stringProperty("BSim URL")),
                List.of(), false, false, true, BsimCorpusOperations::ingest),
            BsimOperation.of("update_metadata", "Apply staged BSim metadata update XML.",
                Map.of("xml_directory", BsimSupport.stringProperty("Artifact-relative XML directory"),
                    "programs", Map.of("type", "array", "items", Map.of("type", "string")),
                    "database", BsimSupport.stringProperty("Connection profile"), "database_url", BsimSupport.stringProperty("BSim URL")),
                List.of(), false, false, true, BsimCorpusOperations::updateMetadata),
            BsimOperation.of("remove_executables", "Remove exactly identified executables from BSim.",
                Map.of("md5", BsimSupport.stringProperty("Exact executable MD5"), "name", BsimSupport.stringProperty("Exact executable name"),
                    "dry_run", Map.of("type", "boolean"), "apply", Map.of("type", "boolean"),
                    "database", BsimSupport.stringProperty("Connection profile"), "database_url", BsimSupport.stringProperty("BSim URL")),
                List.of(), false, true, false, BsimCorpusOperations::removeExecutables),
            BsimOperation.of("export", "Export selected BSim executable/function records to a staged XML artifact.",
                Map.of("output_file", BsimSupport.stringProperty("Artifact-relative output XML"),
                    "md5", BsimSupport.stringProperty("Exact executable MD5"), "name", BsimSupport.stringProperty("Exact executable name"),
                    "database", BsimSupport.stringProperty("Connection profile")),
                List.of("output_file"), true, false, true, BsimCorpusOperations::export),
            BsimOperation.of("rebuild_corpus", "Copy a source BSim corpus into a separate destination corpus.",
                Map.of("source_database", BsimSupport.stringProperty("Source connection profile"),
                    "destination_database", BsimSupport.stringProperty("Separate destination connection profile"), "create_destination", Map.of("type", "boolean"), "template", BsimSupport.stringProperty("Template for creating the destination")), List.of("destination_database"), false, true, true,
                BsimCorpusOperations::rebuildCorpus));
    }

    private static Map<String, Object> generateSignatures(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        Path out = artifactPath(context, BsimSupport.text(args, "output_directory"));
        Files.createDirectories(out);
        FunctionDatabase database = null;
        try {
            LSHVectorFactory vectors;
            String databaseArg = BsimSupport.text(args, "database", null);
            String url = BsimSupport.text(args, "database_url", null);
            if (databaseArg != null || url != null || args.containsKey("profile_id")) {
                database = context.database(args);
                vectors = database.getLSHVectorFactory();
                args = metadataArgs(args, database.getInfo());
            }
            else {
                String template = BsimSupport.text(args, "config").replaceFirst("\\.xml$", "");
                if (template == null) throw new IllegalArgumentException("config or database is required");
                var cfg = FunctionDatabase.loadConfigurationTemplate(template);
                vectors = FunctionDatabase.generateLSHVectorFactory();
                vectors.set(cfg.weightfactory, cfg.idflookup, cfg.info.settings);
                args = metadataArgs(args, cfg.info);
            }
            if (BsimSupport.bool(args, "metadata_only", false)) {
                generateMetadataToDirectory(context, args, monitor, out, vectors);
                return Map.of("operation", "generate_signatures", "metadata_only", true,
                    "files", xmlFiles(out, "update_").stream().map(p -> Map.of("path", p.toString())).toList());
            }
            List<Map<String, Object>> generated = generateToDirectory(context, args, monitor, out, vectors);
            return Map.of("operation", "generate_signatures", "files", generated);
        }
        finally { if (database != null) database.close(); }
    }

    private static List<Map<String, Object>> generateToDirectory(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor, Path out, LSHVectorFactory vectors) throws Exception {
        Files.createDirectories(out);
        List<BsimContext.ProgramHandle> handles = context.resolvePrograms(args, monitor);
        List<Map<String, Object>> generated = new ArrayList<>();
        try {
            for (BsimContext.ProgramHandle handle : handles) {
                monitor.checkCancelled();
                var program = handle.program();
                BsimSupport.requireSaved(program);
                String checkpoint = "generate:" + handle.identity();
                Map<String, Object> prior = context.completed(checkpoint);
                if (prior != null) {
                    if (!(prior.get("path") instanceof String priorName) || !(prior.get("sha256") instanceof String priorHash))
                        throw new IOException("Completed signature checkpoint lacks artifact hash: " + handle.identity());
                    Path priorPath = Path.of(priorName).toAbsolutePath().normalize();
                    if (!priorPath.startsWith(out.toAbsolutePath().normalize()) || !Files.isRegularFile(priorPath) ||
                        !priorHash.equals(sha256(priorPath)))
                        throw new IOException("Completed signature artifact changed or is missing: " + priorName);
                    generated.add(prior); continue;
                }
                Map<String, Object> pending = context.pending(checkpoint);
                Path pendingPath = pending != null && pending.get("path") instanceof String p ? Path.of(p) : null;
                if (pendingPath != null && !pendingPath.toAbsolutePath().normalize().startsWith(out.toAbsolutePath().normalize()))
                    throw new IOException("Pending signature path escaped artifact directory");
                GenSignatures generator = new GenSignatures(true);
                try {
                    configureGenerator(generator, args);
                    generator.setVectorFactory(vectors);
                    java.net.URL programUrl = new java.net.URL(handle.identity());
                    generator.openProgram(program, null, null, null,
                        ghidra.framework.protocol.ghidra.GhidraURL.getProjectURL(programUrl).toString(),
                        ghidra.framework.protocol.ghidra.GhidraURL.getProjectPathname(programUrl));
                    var selected = selectedFunctions(program, args);
                    generator.scanFunctions(selected.iterator(), selected.size(), monitor);
                    String stem = safeStem(handle.identity());
                    Path file = pendingPath != null ? pendingPath : uniquePath(out, "sigs_" + stem + ".xml");
                    if (pending == null) context.begin(checkpoint, Map.of("identity", handle.identity(), "path", file.toString()));
                    // DescriptionManager emits the executable/function records; InsertRequest supplies the envelope.
                    try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                        writer.write("<insert>\n");
                        generator.getDescriptionManager().saveXml(writer);
                        writer.write("</insert>\n");
                    }
                    Map<String, Object> item = Map.of("identity", handle.identity(), "path", file.toString(),
                        "functions", generator.getDescriptionManager().numFunctions(), "sha256", sha256(file));
                    generated.add(item);
                    context.checkpoint(checkpoint, item);
                }
                finally { generator.dispose(); }
            }
        }
        finally { closeHandles(handles); }
        return generated;
    }

    private static void generateMetadataToDirectory(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor, Path out, LSHVectorFactory vectors) throws Exception {
        Files.createDirectories(out);
        List<BsimContext.ProgramHandle> handles = context.resolvePrograms(args, monitor);
        try {
            for (BsimContext.ProgramHandle handle : handles) {
                monitor.checkCancelled();
                String checkpoint = "metadata-generate:" + handle.identity();
                if (context.completed(checkpoint) != null) continue;
                var program = handle.program();
                BsimSupport.requireSaved(program);
                GenSignatures generator = new GenSignatures(false);
                try {
                    configureGenerator(generator, args);
                    generator.setVectorFactory(vectors);
                    java.net.URL programUrl = new java.net.URL(handle.identity());
                    generator.openProgram(program, null, null, null,
                        ghidra.framework.protocol.ghidra.GhidraURL.getProjectURL(programUrl).toString(),
                        ghidra.framework.protocol.ghidra.GhidraURL.getProjectPathname(programUrl));
                    generator.scanFunctionsMetadata(selectedFunctions(program, args).iterator(), monitor);
                    Path file = uniquePath(out, "update_" + safeStem(handle.identity()) + ".xml");
                    if (context.pending(checkpoint) == null)
                        context.begin(checkpoint, Map.of("identity", handle.identity(), "path", file.toString()));
                    try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                        writer.write("<update>\n");
                        generator.getDescriptionManager().saveXml(writer);
                        writer.write("</update>\n");
                    }
                    Map<String, Object> item = Map.of("identity", handle.identity(), "path", file.toString(),
                        "functions", generator.getDescriptionManager().numFunctions(), "sha256", sha256(file));
                    context.checkpoint(checkpoint, item);
                } finally { generator.dispose(); }
            }
        } finally { closeHandles(handles); }
    }

    private static Map<String, Object> ingest(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        try (FunctionDatabase database = context.database(args)) {
            String xmlDirectory = BsimSupport.text(args, "xml_directory", null);
            Path generatedDirectory = null;
            if (xmlDirectory == null) {
                if (!args.containsKey("programs")) throw new IllegalArgumentException("xml_directory or programs is required");
                generatedDirectory = context.artifacts().resolve(".bsim-ingest-" + safeStem(context.jobId()));
                generateToDirectory(context, metadataArgs(args, database.getInfo()), monitor, generatedDirectory, database.getLSHVectorFactory());
            }
            Path input = xmlDirectory == null ? generatedDirectory : artifactPath(context, xmlDirectory);
            List<Path> files = Files.isRegularFile(input) ? List.of(input) : xmlFiles(input, "sigs_");
            List<Map<String, Object>> results = new ArrayList<>();
            try {
                for (Path file : files) {
                    monitor.checkCancelled();
                    String checkpoint = "ingest:" + file.getFileName();
                    Map<String, Object> prior = context.completed(checkpoint);
                    if (prior != null) {
                        verifyArtifactCheckpoint(prior, file);
                        results.add(prior); continue;
                    }
                    InsertRequest request = new InsertRequest();
                    loadXml(file, request, database.getLSHVectorFactory());
                    if (request.manage.numFunctions() == 0) throw new IOException("Empty signature file: " + file);
                    String digest = sha256(file);
                    Map<String, Object> pending = context.pending(checkpoint);
                    if (pending == null) context.begin(checkpoint, Map.of("file", file.toString(), "sha256", digest));
                    else if (!digest.equals(pending.get("sha256"))) throw new IOException("Staged file changed while insert was pending: " + file);
                    var exes = request.manage.getExecutableRecordSet();
                    if (!exes.isEmpty() && allExecutablesPresent(database, request.manage)) {
                        Map<String, Object> item = Map.of("file", file.toString(), "functions", request.manage.numFunctions(),
                            "sha256", digest, "reconciled", true);
                        context.checkpoint(checkpoint, item); results.add(item); continue;
                    }
                    QueryResponseRecord response = BsimSupport.query(database, request);
                    Map<String, Object> item = Map.of("file", file.toString(), "functions", request.manage.numFunctions(), "sha256", digest);
                    results.add(item);
                    context.checkpoint(checkpoint, item);
                }
            } finally { }
            return Map.of("operation", "ingest", "files", results);
        }
    }

    private static Map<String, Object> updateMetadata(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        try (FunctionDatabase database = context.database(args)) {
            String xmlDirectory = BsimSupport.text(args, "xml_directory", null);
            Path generatedDirectory = null;
            if (xmlDirectory == null) {
                if (!args.containsKey("programs")) throw new IllegalArgumentException("xml_directory or programs is required");
                generatedDirectory = context.artifacts().resolve(".bsim-metadata-" + safeStem(context.jobId()));
                generateMetadataToDirectory(context, metadataArgs(args, database.getInfo()), monitor, generatedDirectory, database.getLSHVectorFactory());
            }
            List<Path> files = xmlFiles(xmlDirectory == null ? generatedDirectory : artifactPath(context, xmlDirectory), "update_");
            List<Map<String, Object>> results = new ArrayList<>();
            try { for (Path file : files) {
                monitor.checkCancelled();
                String checkpoint = "metadata:" + file.getFileName();
                Map<String, Object> prior = context.completed(checkpoint);
                if (prior != null) {
                    verifyArtifactCheckpoint(prior, file);
                    results.add(prior); continue;
                }
                QueryUpdate request = new QueryUpdate();
                loadXml(file, request, database.getLSHVectorFactory());
                String digest = sha256(file);
                Map<String, Object> pending = context.pending(checkpoint);
                if (pending == null) context.begin(checkpoint, Map.of("file", file.toString(), "sha256", digest));
                else if (!digest.equals(pending.get("sha256"))) throw new IOException("Metadata XML changed while pending: " + file);
                QueryResponseRecord response = BsimSupport.query(database, request);
                Map<String, Object> item = Map.of("file", file.toString(), "functions", request.manage.numFunctions(), "sha256", digest);
                results.add(item);
                context.checkpoint(checkpoint, item);
            }} finally { }
            return Map.of("operation", "update_metadata", "files", results);
        }
    }

    private static Map<String, Object> removeExecutables(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        String md5 = BsimSupport.text(args, "md5", null);
        String name = BsimSupport.text(args, "name", null);
        if ((md5 == null || md5.isBlank()) == (name == null || name.isBlank()))
            throw new IllegalArgumentException("provide exactly one of md5 or name");
        monitor.checkCancelled();
        try (FunctionDatabase database = context.database(args)) {
            QueryExeInfo lookup = new QueryExeInfo();
            lookup.limit = MAX_RESULTS; lookup.includeFakes = true;
            lookup.filterMd5 = md5;
            lookup.filterExeName = name;
            ResponseExe found = BsimSupport.query(database, lookup);
            List<Map<String, Object>> candidates = found.records.stream()
                .filter(exe -> md5 != null ? exe.getMd5().equalsIgnoreCase(md5) : exe.getNameExec().equals(name))
                .map(exe -> Map.<String, Object>of(
                "md5", exe.getMd5(), "name", exe.getNameExec())).toList();
            boolean apply = BsimSupport.bool(args, "apply", false);
            boolean dryRun = BsimSupport.bool(args, "dry_run", !apply);
            if (!apply || dryRun) return Map.of("operation", "remove_executables", "preview", true, "candidates", candidates);
            if (candidates.size() != 1) throw new IllegalArgumentException("removal selector is not unique; refine md5 or name");
            QueryDelete query = new QueryDelete();
            ExeSpecifier spec = new ExeSpecifier();
            spec.exemd5 = candidates.get(0).get("md5").toString();
            query.addSpecifier(spec);
            ResponseDelete response = BsimSupport.query(database, query);
            return Map.of("operation", "remove_executables", "removed", response.reslist.size(),
                "missed", response.missedlist.size());
        }
    }

    private static Map<String, Object> export(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        String md5 = BsimSupport.text(args, "md5", null);
        String name = BsimSupport.text(args, "name", null);
        if ((md5 == null || md5.isBlank()) && (name == null || name.isBlank()))
            throw new IllegalArgumentException("md5 or name is required");
        Path output = artifactPath(context, BsimSupport.text(args, "output_file"));
        Files.createDirectories(Objects.requireNonNull(output.getParent()));
        try (FunctionDatabase database = context.database(args)) {
            QueryName query = new QueryName();
            query.spec.exemd5 = md5; query.spec.exename = name; query.funcname = "";
            query.maxfunc = MAX_RESULTS; query.fillinSigs = true; query.fillinCallgraph = true;
            ResponseName response = BsimSupport.query(database, query);
            if (response.manage.numFunctions() >= MAX_RESULTS)
                throw new IllegalArgumentException("export exceeds bounded function limit; narrow md5/name selector");
            try (Writer writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
                writer.write("<insert>\n");
                response.manage.saveXml(writer);
                writer.write("</insert>\n");
            }
            Path weightsFile = output.resolveSibling(output.getFileName() + ".signature-config.json");
            Files.writeString(weightsFile, BsimSupport.vectorConfiguration(database.getLSHVectorFactory()), StandardCharsets.UTF_8);
            Path provenance = output.resolveSibling(output.getFileName() + ".json");
            var info = database.getInfo();
            BsimSupport.atomicJson(provenance, Map.of("format", "BSim insert XML", "source_url",
                BsimSupport.redact(database.getURLString()), "database", info.databasename,
                "settings", info.settings, "major", info.major, "minor", info.minor,
                "md5", md5 == null ? "" : md5, "name", name == null ? "" : name,
                "functions", response.manage.numFunctions()));
            return Map.of("operation", "export", "path", output.toString(), "provenance", provenance.toString(),
                "functions", response.manage.numFunctions());
        }
    }

    private static Map<String, Object> rebuildCorpus(BsimContext context, Map<String, Object> args,
            TaskMonitor monitor) throws Exception {
        monitor.checkCancelled();
        String destination = BsimSupport.text(args, "destination_database");
        String source = BsimSupport.text(args, "source_database", null);
        if (destination.equals(source)) throw new IllegalArgumentException("destination must differ from source");
        Map<String, Object> sourceArgs = new HashMap<>(args);
        if (source != null) { sourceArgs.put("database", source); sourceArgs.remove("database_url"); }
        sourceArgs.remove("destination_database");
        Map<String, Object> destArgs = new HashMap<>(args);
        destArgs.put("database", destination);
        destArgs.remove("source_database");
        destArgs.remove("database_url");
        if (BsimSupport.bool(args, "create_destination", false)) {
            String template = BsimSupport.text(args, "template", null);
            if (template == null) throw new IllegalArgumentException("template is required when create_destination is true");
            try (FunctionDatabase ignored = context.database(destArgs)) {
                // Destination already exists; compatibility is checked below.
            } catch (Exception missing) {
                BsimOperation create = BsimDatabaseOperations.operations().stream()
                    .filter(operation -> operation.name().equals("create_database")).findFirst().orElseThrow();
                Map<String, Object> createArgs = new HashMap<>(destArgs);
                createArgs.put("template", template);
                createArgs.putIfAbsent("name", destination);
                create.handler().execute(context, createArgs, monitor);
            }
        }
        int copied = 0;
        try (FunctionDatabase from = context.database(sourceArgs); FunctionDatabase to = context.database(destArgs)) {
            if (BsimSupport.redact(from.getURLString()).equals(BsimSupport.redact(to.getURLString())))
                throw new IllegalArgumentException("source and destination resolve to the same BSim database");
            var sourceInfo = from.getInfo();
            var destinationInfo = to.getInfo();
            boolean destinationEmpty = destinationInfo.major == 0;
            boolean sameWeights = BsimSupport.vectorConfiguration(from.getLSHVectorFactory()).equals(BsimSupport.vectorConfiguration(to.getLSHVectorFactory()));
            if (!sameWeights || !destinationEmpty && (sourceInfo.major != destinationInfo.major || sourceInfo.minor != destinationInfo.minor)) {
                if (!args.containsKey("programs"))
                    throw new IllegalArgumentException("source and destination BSim signature settings are incompatible; provide programs to regenerate");
                Path regenerated = context.artifacts().resolve(".bsim-rebuild-" + safeStem(context.jobId()));
                {
                    Map<String, Object> generationArgs = new HashMap<>(args);
                    generationArgs.put("database", destination);
                    generationArgs.remove("source_database"); generationArgs.remove("destination_database");
                    List<Map<String, Object>> files = generateToDirectory(context, metadataArgs(generationArgs, to.getInfo()), monitor, regenerated, to.getLSHVectorFactory());
                    for (Map<String, Object> file : files) {
                        Path path = Path.of((String) file.get("path"));
                        InsertRequest insert = new InsertRequest();
                        loadXml(path, insert, to.getLSHVectorFactory());
                        String unit = "regenerate-insert:" + file.get("identity");
                        String hash = sha256(path);
                        context.validateIdentity(unit, Map.of("sha256", hash));
                        if (context.completed(unit) == null && context.pending(unit) == null) context.begin(unit, Map.of("sha256", hash));
                        if (!allExecutablesPresent(to, insert.manage)) BsimSupport.query(to, insert);
                        context.checkpoint(unit, Map.of("sha256", hash, "functions", insert.manage.numFunctions()));
                    }
                    return Map.of("operation", "rebuild_corpus", "destination", destination,
                        "regenerated", true, "source_preserved", true, "files", files);
                }
            }
            QueryExeInfo listQuery = new QueryExeInfo();
            listQuery.limit = MAX_RESULTS; listQuery.includeFakes = true;
            ResponseExe list = BsimSupport.query(from, listQuery);
            if (list.recordCount > MAX_RESULTS || list.records.size() >= MAX_RESULTS)
                throw new IllegalArgumentException("source corpus exceeds bounded executable limit");
            for (var exe : list.records) {
                monitor.checkCancelled();
                String checkpoint = "rebuild:" + exe.getMd5();
                if (context.pending(checkpoint) == null && context.completed(checkpoint) == null)
                    context.begin(checkpoint, Map.of("md5", exe.getMd5(), "source", source == null ? "default" : source,
                        "destination", destination));
                QueryName nameQuery = new QueryName();
                nameQuery.spec.exemd5 = exe.getMd5(); nameQuery.funcname = "";
                nameQuery.maxfunc = MAX_RESULTS; nameQuery.fillinSigs = true; nameQuery.fillinCallgraph = true;
                ResponseName sourceData = BsimSupport.query(from, nameQuery);
                if (sourceData.manage.numFunctions() == 0) throw new IOException("Source executable has no functions: " + exe.getNameExec() + ":" + exe.getMd5());
                if (sourceData.manage.numFunctions() >= MAX_RESULTS) throw new IOException("Executable exceeds export function bound: " + exe.getMd5());
                QueryExeInfo destinationCheck = new QueryExeInfo();
                destinationCheck.limit = 2; destinationCheck.filterMd5 = exe.getMd5();
                ResponseExe already = BsimSupport.query(to, destinationCheck);
                if (!already.records.isEmpty()) {
                    QueryName destinationFunctions = new QueryName();
                    destinationFunctions.spec.exemd5 = exe.getMd5(); destinationFunctions.maxfunc = MAX_RESULTS;
                    ResponseName destinationData = BsimSupport.query(to, destinationFunctions);
                    if (destinationData.manage.numFunctions() != sourceData.manage.numFunctions())
                        throw new IOException("Destination contains partial executable during rebuild: " + exe.getMd5());
                    copied++;
                    context.checkpoint(checkpoint, Map.of("md5", exe.getMd5(), "name", exe.getNameExec(), "reconciled", true));
                    continue;
                }
                InsertRequest insert = new InsertRequest();
                // SQL row IDs belong to the source database. Native XML deliberately strips them.
                Path staged = context.artifacts().resolve(".bsim-rebuild-" + safeStem(context.jobId())).resolve("sigs_" + exe.getMd5() + ".xml");
                Files.createDirectories(staged.getParent());
                try (Writer writer = Files.newBufferedWriter(staged, StandardCharsets.UTF_8)) {
                    writer.write("<insert>\n"); sourceData.manage.saveXml(writer); writer.write("</insert>\n");
                }
                loadXml(staged, insert, to.getLSHVectorFactory());
                BsimSupport.query(to, insert);
                QueryName verify = new QueryName(); verify.spec.exemd5 = exe.getMd5(); verify.maxfunc = MAX_RESULTS;
                var verified = BsimSupport.query(to, verify);
                if (verified.manage.numFunctions() != sourceData.manage.numFunctions()) throw new IOException("Rebuilt executable verification failed: expected " + sourceData.manage.numFunctions() + ", got " + verified.manage.numFunctions());
                copied++;
                context.checkpoint(checkpoint, Map.of("md5", exe.getMd5(), "name", exe.getNameExec()));
            }
            return Map.of("operation", "rebuild_corpus", "source", source == null ? "default" : source, "destination", destination,
                "copied_executables", copied, "source_preserved", true);
        }
    }

    private static Map<String, Object> metadataArgs(Map<String, Object> args, ghidra.features.bsim.query.description.DatabaseInformation info) {
        var copy = new HashMap<>(args);
        copy.put("_categories", info.execats == null ? List.of() : info.execats);
        copy.put("_tags", info.functionTags == null ? List.of() : info.functionTags);
        if (info.dateColumnName != null) copy.put("_date", info.dateColumnName);
        return copy;
    }
    @SuppressWarnings("unchecked") private static void configureGenerator(GenSignatures generator, Map<String, Object> args) {
        generator.addExecutableCategories((List<String>) args.get("_categories"));
        generator.addFunctionTags((List<String>) args.get("_tags"));
        generator.addDateColumnName((String) args.get("_date"));
    }
    private static List<Function> selectedFunctions(ghidra.program.model.listing.Program program, Map<String, Object> args) {
        List<Function> result = new ArrayList<>();
        if (args.get("addresses") instanceof List<?> addresses) {
            for (Object item : addresses) {
                if (!(item instanceof String text)) throw new IllegalArgumentException("addresses must be hex strings");
                var address = program.getAddressFactory().getAddress(text);
                var function = address == null ? null : program.getFunctionManager().getFunctionAt(address);
                if (function == null) throw new IllegalArgumentException("Function not found at " + text);
                if (!result.contains(function)) result.add(function);
            }
        } else {
            for (Function function : program.getFunctionManager().getFunctions(true)) result.add(function);
        }
        return result;
    }

    private static List<Path> xmlFiles(Path dir, String prefix) throws IOException {
        if (!Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Not an artifact directory: " + dir);
        try (var stream = Files.list(dir)) {
            List<Path> files = stream.filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                .filter(p -> p.getFileName().toString().startsWith(prefix) && p.getFileName().toString().endsWith(".xml"))
                .sorted().limit(MAX_FILES + 1L).collect(Collectors.toList());
            if (files.size() > MAX_FILES) throw new IOException("too many XML files");
            return files;
        }
    }

    private static void loadXml(Path file, ghidra.features.bsim.query.protocol.BSimQuery<?> request,
            LSHVectorFactory vectors) throws Exception {
        var handler = SpecXmlUtils.getXmlHandler();
        XmlPullParser parser = new NonThreadedXmlPullParserImpl(file.toFile(), handler, false);
        try { request.restoreXml(parser, vectors); }
        finally { parser.dispose(); }
    }

    private static IOException dbError(FunctionDatabase db, String prefix) {
        var error = db.getLastError();
        return new IOException(prefix + ": " + (error == null ? "unknown database error" : error.message));
    }

    private static boolean allExecutablesPresent(FunctionDatabase database, DescriptionManager manager) throws Exception {
        boolean any = false;
        for (var executable : manager.getExecutableRecordSet()) {
            String md5 = executable.getMd5();
            if (md5 == null || md5.isBlank()) continue;
            any = true;
            QueryExeInfo lookup = new QueryExeInfo();
            lookup.limit = 2; lookup.filterMd5 = md5; lookup.includeFakes = true;
            ResponseExe existing = BsimSupport.query(database, lookup);
            if (existing.records.isEmpty()) return false;
            QueryName count = new QueryName();
            count.spec.exemd5 = md5; count.maxfunc = MAX_RESULTS;
            ResponseName functions = BsimSupport.query(database, count);
            int expected = 0;
            var candidates = manager.listFunctions(executable);
            while (candidates.hasNext()) { candidates.next(); expected++; }
            if (functions.manage.numFunctions() != expected)
                throw new IOException("Pending insert found partial executable in BSim: " + md5);
        }
        return any;
    }

    private static Path artifactPath(BsimContext context, String value) throws IOException {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("artifact path is required");
        Path root = context.artifacts().toAbsolutePath().normalize();
        Path path = root.resolve(value).normalize();
        if (!path.startsWith(root)) throw new IllegalArgumentException("artifact path escapes workspace");
        Path ancestor = path;
        while (!Files.exists(ancestor, LinkOption.NOFOLLOW_LINKS)) ancestor = ancestor.getParent();
        if (!ancestor.toRealPath().startsWith(root.toRealPath())) throw new IllegalArgumentException("artifact path traverses an external link");
        return path;
    }

    private static Path uniquePath(Path dir, String name) throws IOException {
        Path path = dir.resolve(name);
        if (!Files.exists(path)) return path;
        for (int i = 1; i < MAX_FILES; i++) {
            int dot = name.lastIndexOf('.');
            Path candidate = dir.resolve(dot < 0 ? name + "-" + i : name.substring(0, dot) + "-" + i + name.substring(dot));
            if (!Files.exists(candidate)) return candidate;
        }
        throw new IOException("too many output files");
    }

    private static String safeStem(String value) {
        String stem = value == null ? "program" : value.replaceAll("[^A-Za-z0-9_.-]", "_");
        return stem.isBlank() ? "program" : stem.substring(0, Math.min(stem.length(), 180));
    }

    private static String sha256(Path file) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }

    private static void verifyArtifactCheckpoint(Map<String, Object> checkpoint, Path expected) throws IOException {
        if (!(checkpoint.get("sha256") instanceof String digest) || !Files.isRegularFile(expected) ||
            !digest.equals(sha256(expected)))
            throw new IOException("Completed staged artifact changed or is missing: " + expected);
    }

    private static void closeHandles(List<BsimContext.ProgramHandle> handles) {
        if (handles == null) return;
        for (var handle : handles) {
            try { handle.close(); } catch (Exception ignored) { }
        }
    }

}
