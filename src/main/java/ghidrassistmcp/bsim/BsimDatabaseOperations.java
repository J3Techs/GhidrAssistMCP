package ghidrassistmcp.bsim;

import java.io.IOException;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import ghidra.features.bsim.query.protocol.DropDatabase;
import ghidra.features.bsim.query.protocol.InstallMetadataRequest;
import ghidra.features.bsim.query.protocol.InstallCategoryRequest;
import ghidra.features.bsim.query.protocol.InstallTagRequest;
import ghidra.features.bsim.query.protocol.AdjustVectorIndex;
import ghidra.features.bsim.query.protocol.PrewarmRequest;
import ghidra.features.bsim.query.protocol.ResponseDropDatabase;
import ghidra.features.bsim.query.protocol.ResponseAdjustIndex;
import ghidra.features.bsim.query.protocol.ResponsePrewarm;
import ghidra.features.bsim.query.protocol.ResponseInfo;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.util.task.TaskMonitor;

/** Explicit, typed BSim connection and database lifecycle operations. */
public final class BsimDatabaseOperations {
    private static final int MAX_TEXT = 512;

    private BsimDatabaseOperations() {}

    public static List<BsimOperation> operations() {
        return List.of(
            BsimOperation.of("list_connections", "List secret-free saved BSim connection profiles.",
                Map.of(), List.of(), true, false, false, BsimDatabaseOperations::listConnections),
            BsimOperation.of("configure_connection", "Atomically save a secret-free BSim connection profile.",
                schema("profile_id", stringSchema(), "database_url", stringSchema(), "user", stringSchema(), "keystore", stringSchema()), List.of("database_url"),
                false, false, false, BsimDatabaseOperations::configureConnection),
            BsimOperation.of("remove_connection", "Remove a saved BSim connection profile.",
                schema("profile_id", stringSchema(), "confirm", booleanSchema()), List.of("profile_id"), false, true, false,
                BsimDatabaseOperations::removeConnection),
            BsimOperation.of("database_info", "Return BSim database metadata and connection health.",
                schema("profile_id", stringSchema(), "database_url", stringSchema(), "database", stringSchema()), List.of(), true, false,
                false, BsimDatabaseOperations::databaseInfo),
            BsimOperation.of("list_templates", "List installed BSim signature configuration templates.",
                Map.of(), List.of(), true, false, false, BsimDatabaseOperations::listTemplates),
            BsimOperation.of("create_database", "Create a BSim database using an installed template.",
                schema("profile_id", stringSchema(), "database_url", stringSchema(), "database", stringSchema(), "template", stringSchema(),
                    "name", stringSchema(), "owner", stringSchema(), "description", stringSchema()),
                List.of("template"), false, false, true, BsimDatabaseOperations::createDatabase),
            BsimOperation.of("update_database", "Update editable BSim database metadata.",
                schema("profile_id", stringSchema(), "database_url", stringSchema(), "database", stringSchema(), "name", stringSchema(),
                    "owner", stringSchema(), "description", stringSchema(), "category", stringSchema(),
                    "datecolumn", stringSchema(), "date_column", stringSchema(), "functiontags", arraySchema(),
                    "function_tags", arraySchema()), List.of(), false, false, false,
                BsimDatabaseOperations::updateDatabase),
            BsimOperation.of("drop_database", "Drop a BSim database through its stock protocol.",
                schema("profile_id", stringSchema(), "database_url", stringSchema(), "database", stringSchema(), "confirm", booleanSchema()),
                List.of("confirm"), false, true, true, BsimDatabaseOperations::dropDatabase),
            BsimOperation.of("maintain_database", "Check BSim database readiness and layout compatibility.",
                schema("profile_id", stringSchema(), "database_url", stringSchema(), "database", stringSchema(),
                    "drop_index", booleanSchema(), "rebuild_index", booleanSchema(), "prewarm", booleanSchema()), List.of(), false, true,
                true, BsimDatabaseOperations::maintainDatabase));
    }

    private static Map<String, Object> listConnections(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        return Map.of("connections", c.connections().list(),
            "discovered", c.connections().discoverSavedDefinitions(),
            "backend_capabilities", BsimConnections.backendCapabilities());
    }

    private static Map<String, Object> configureConnection(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        return Map.of("connection", c.connections().configure(a), "persisted", true);
    }

    private static Map<String, Object> removeConnection(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        if (!BsimSupport.bool(a, "confirm", false)) {
            throw new IllegalArgumentException("confirm=true is required to remove a connection");
        }
        String id = BsimSupport.text(a, "profile_id");
        return Map.of("profile_id", id, "removed", c.connections().remove(id));
    }

    private static Map<String, Object> databaseInfo(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        try (FunctionDatabase db = c.database(a)) {
            return info(db);
        }
    }

    private static Map<String, Object> listTemplates(BsimContext c, Map<String, Object> a,
            TaskMonitor m) {
        List<String> templates = new ArrayList<>();
        for (File file : FunctionDatabase.getConfigurationTemplates()) {
            templates.add(templateId(file.getName()));
        }
        templates.sort(String::compareTo);
        return Map.of("templates", templates);
    }

    private static Map<String, Object> createDatabase(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        String template = templateId(BsimSupport.text(a, "template"));
        String checkpoint = "create_database:" + selectorIdentity(a);
        Map<String, Object> prior = c.completed(checkpoint);
        if (prior != null) return prior;
        String requestedName = optionalText(a, "name");
        // A pending record is evidence of a previously submitted create, not proof
        // that an arbitrary existing database may be adopted.  Probe first, then
        // record the resolved target immediately before issuing CreateDatabase.
        Map<String, Object> pending = c.pending(checkpoint);
        try (FunctionDatabase db = c.connections().open(a, false)) {
            String resolvedUrl = BsimSupport.redact(db.getURLString());
            boolean exists = db.initialize();
            if (exists) {
                Map<String, Object> existing = responseInfo(db.getInfo());
                if (pending != null && pendingCreateMatches(pending, resolvedUrl, template,
                        requestedName) && requestedName != null && requestedName.equals(existing.get("name"))) {
                    existing.put("reconciled", true);
                    c.checkpoint(checkpoint, existing);
                    return existing;
                }
                throw new IllegalStateException("BSim database already exists; refusing to adopt it");
            }
            if (pending != null) {
                throw new IllegalStateException("previous BSim create is pending but the target is absent; refusing an automatic retry");
            }
            FunctionDatabase.BSimError lastError = db.getLastError();
            if (lastError != null && lastError.category != FunctionDatabase.ErrorCategory.Nodatabase) {
                throw new IOException("cannot determine whether BSim database exists: " + lastError.message);
            }
            c.begin(checkpoint, Map.of("database", resolvedUrl, "template", template,
                "name", requestedName == null ? "" : requestedName));
            CreateDatabase query = new CreateDatabase();
            query.config_template = template;
            query.info = new DatabaseInformation();
            String name = requestedName;
            String owner = optionalText(a, "owner");
            String description = optionalText(a, "description");
            if (name != null) query.info.databasename = name;
            if (owner != null) query.info.owner = owner;
            if (description != null) query.info.description = description;
            ResponseInfo response = BsimSupport.query(db, query);
            Map<String, Object> result = responseInfo(response.info);
            c.checkpoint(checkpoint, result);
            return result;
        }
    }

    private static Map<String, Object> updateDatabase(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        try (FunctionDatabase db = c.database(a)) {
            InstallMetadataRequest query = new InstallMetadataRequest();
            query.dbname = optionalText(a, "name");
            query.owner = optionalText(a, "owner");
            query.description = optionalText(a, "description");
            if (query.dbname == null && query.owner == null && query.description == null &&
                !a.containsKey("category") && !a.containsKey("datecolumn") && !a.containsKey("date_column") &&
                !a.containsKey("functiontags") && !a.containsKey("function_tags")) {
                throw new IllegalArgumentException("at least one metadata field is required");
            }
            ResponseInfo response = null;
            if (query.dbname != null || query.owner != null || query.description != null) {
                response = BsimSupport.query(db, query);
            }
            if (a.containsKey("category")) {
                InstallCategoryRequest category = new InstallCategoryRequest();
                category.type_name = optionalText(a, "category");
                response = BsimSupport.query(db, category);
            }
            if (a.containsKey("datecolumn") || a.containsKey("date_column")) {
                InstallCategoryRequest date = new InstallCategoryRequest();
                date.type_name = optionalText(a, a.containsKey("datecolumn") ? "datecolumn" : "date_column");
                date.isdatecolumn = true;
                response = BsimSupport.query(db, date);
            }
            if (a.containsKey("functiontags") || a.containsKey("function_tags")) {
                Object raw = a.get(a.containsKey("functiontags") ? "functiontags" : "function_tags");
                if (!(raw instanceof List<?> tags) || tags.size() > 100) throw new IllegalArgumentException("functiontags must be an array of at most 100 strings");
                for (Object tag : tags) {
                    if (!(tag instanceof String value) || value.isBlank()) throw new IllegalArgumentException("functiontags entries must be nonempty strings");
                    InstallTagRequest request = new InstallTagRequest();
                    request.tag_name = value.trim();
                    response = BsimSupport.query(db, request);
                }
            }
            if (response == null) response = BsimSupport.query(db, new InstallMetadataRequest());
            return responseInfo(response.info);
        }
    }

    private static Map<String, Object> dropDatabase(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        if (!BsimSupport.bool(a, "confirm", false)) {
            throw new IllegalArgumentException("confirm=true is required to drop a database");
        }
        String checkpoint = "drop_database:" + selectorIdentity(a);
        Map<String, Object> prior = c.completed(checkpoint);
        if (prior != null) return prior;
        c.begin(checkpoint, Map.of("database", selectorIdentity(a)));
        // DropDatabase is one of the stock protocol operations explicitly allowed
        // before initialize(), which also lets it report an already-missing target.
        try (FunctionDatabase db = c.connections().open(a, false)) {
            DropDatabase query = new DropDatabase();
            query.databaseName = db.getServerInfo().getDBName();
            ResponseDropDatabase response = BsimSupport.query(db, query);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("operation_supported", response.operationSupported);
            result.put("dropped", response.dropSuccessful);
            if (response.errorMessage != null) result.put("error", response.errorMessage);
            if (!response.dropSuccessful) throw new IOException(response.errorMessage);
            c.checkpoint(checkpoint, result);
            return result;
        }
    }

    private static Map<String, Object> maintainDatabase(BsimContext c, Map<String, Object> a,
            TaskMonitor m) throws Exception {
        try (FunctionDatabase db = c.database(a)) {
            if (db.getServerInfo().getDBType() == ghidra.features.bsim.query.BSimServerInfo.DBType.file) {
                throw new UnsupportedOperationException("index maintenance and prewarm are unsupported for H2");
            }
            boolean rebuild = BsimSupport.bool(a, "rebuild_index", false);
            boolean dropIndex = BsimSupport.bool(a, "drop_index", rebuild);
            boolean prewarm = BsimSupport.bool(a, "prewarm", false);
            Map<String, Object> result = info(db);
            result.put("layout_compatible", db.compareLayout() == 0);
            result.put("status", db.getStatus().toString());
            if (dropIndex) {
                AdjustVectorIndex drop = new AdjustVectorIndex();
                drop.doRebuild = false;
                ResponseAdjustIndex dropped = BsimSupport.query(db, drop);
                result.put("index_drop", Map.of("supported", dropped.operationSupported, "success", dropped.success));
            }
            if (rebuild) {
                AdjustVectorIndex build = new AdjustVectorIndex();
                build.doRebuild = true;
                ResponseAdjustIndex rebuilt = BsimSupport.query(db, build);
                result.put("index_rebuild", Map.of("supported", rebuilt.operationSupported, "success", rebuilt.success));
            }
            if (prewarm && db.getServerInfo().getDBType() == ghidra.features.bsim.query.BSimServerInfo.DBType.postgres) {
                ResponsePrewarm warmed = BsimSupport.query(db, new PrewarmRequest());
                result.put("prewarm", Map.of("supported", warmed.operationSupported, "blocks", warmed.blockCount));
            }
            return result;
        }
    }

    private static Map<String, Object> info(FunctionDatabase db) {
        Map<String, Object> result = responseInfo(db.getInfo());
        result.put("url", BsimSupport.redact(db.getURLString()));
        result.put("status", db.getStatus().toString());
        result.put("connection_type", db.getConnectionType().toString());
        result.put("layout_comparison", db.compareLayout());
        return result;
    }

    private static Map<String, Object> responseInfo(DatabaseInformation info) {
        if (info == null) throw new IllegalStateException("BSim returned no database metadata");
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", info.databasename);
        result.put("owner", info.owner);
        result.put("description", info.description);
        result.put("date_column", info.dateColumnName);
        result.put("major", info.major);
        result.put("minor", info.minor);
        result.put("settings", info.settings);
        result.put("layout_version", info.layout_version);
        result.put("read_only", info.readonly);
        result.put("track_callgraph", info.trackcallgraph);
        result.put("executable_categories", info.execats == null ? List.of() : info.execats);
        result.put("function_tags", info.functionTags == null ? List.of() : info.functionTags);
        List<Map<String, Object>> filterTypes = new ArrayList<>();
        for (BSimFilterType filter : BSimFilterType.generateBsimFilters(info, true)) {
            filterTypes.add(Map.of("label", filter.getLabel(), "xml", filter.getXmlValue(),
                "hint", filter.getHint() == null ? "" : filter.getHint()));
        }
        result.put("filter_types", filterTypes);
        return result;
    }

    private static boolean pendingCreateMatches(Map<String, Object> pending, String resolvedUrl,
            String template, String requestedName) {
        return resolvedUrl.equals(pending.get("database")) && template.equals(pending.get("template")) &&
            (requestedName == null ? "" : requestedName).equals(pending.get("name"));
    }

    private static String optionalText(Map<String, Object> args, String key) {
        if (!args.containsKey(key)) return null;
        String value = BsimSupport.text(args, key);
        if (value.length() > MAX_TEXT) throw new IllegalArgumentException(key + " is too long");
        return value;
    }

    private static String templateId(String value) {
        String id = value == null ? "" : value.trim();
        if (id.endsWith(".xml")) id = id.substring(0, id.length() - 4);
        if (id.isBlank() || id.contains("/") || id.contains("\\") || id.contains("..")) {
            throw new IllegalArgumentException("template must be an installed BSim template id");
        }
        return id;
    }

    private static String selectorIdentity(Map<String, Object> args) {
        for (String key : List.of("database_url", "database", "profile_id")) {
            Object value = args.get(key);
            if (value instanceof String s && !s.isBlank()) return BsimSupport.redact(s.trim());
        }
        return "unspecified";
    }

    private static Map<String, Object> schema(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < values.length; i += 2) result.put((String) values[i], values[i + 1]);
        return result;
    }

    private static Map<String, Object> stringSchema() { return Map.of("type", "string"); }
    private static Map<String, Object> booleanSchema() { return Map.of("type", "boolean"); }
    private static Map<String, Object> arraySchema() { return Map.of("type", "array", "items", stringSchema()); }
}
