/* 
 * 
 */
package ghidrassistmcp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassistmcp.cache.McpCache;
import ghidrassistmcp.decompiler.DecompilerService;
import ghidrassistmcp.prompts.AnalyzeFunctionPrompt;
import ghidrassistmcp.prompts.DocumentFunctionPrompt;
import ghidrassistmcp.prompts.IdentifyVulnerabilityPrompt;
import ghidrassistmcp.prompts.McpPrompt;
import ghidrassistmcp.prompts.McpPromptRegistry;
import ghidrassistmcp.prompts.TraceDataFlowPrompt;
import ghidrassistmcp.prompts.TraceNetworkDataPrompt;
import ghidrassistmcp.resources.ExportsResource;
import ghidrassistmcp.resources.FunctionListResource;
import ghidrassistmcp.resources.ImportsResource;
import ghidrassistmcp.resources.McpResource;
import ghidrassistmcp.resources.McpResourceRegistry;
import ghidrassistmcp.resources.ProgramInfoResource;
import ghidrassistmcp.resources.StringsResource;
import ghidrassistmcp.tasks.McpProgramContext;
import ghidrassistmcp.tasks.McpTask;
import ghidrassistmcp.tasks.McpTaskManager;
import ghidrassistmcp.tools.AnalysisControlTool;
import ghidrassistmcp.tools.AnalysisOptionsTool;
import ghidrassistmcp.tools.AnalyzeProgramTool;
import ghidrassistmcp.tools.AssembleCodeTool;
import ghidrassistmcp.tools.BookmarksTool;
import ghidrassistmcp.tools.CancelTaskTool;
import ghidrassistmcp.tools.ClassTool;
import ghidrassistmcp.tools.CloseProgramTool;
import ghidrassistmcp.tools.CommentsTool;
import ghidrassistmcp.tools.CreateDataVarTool;
import ghidrassistmcp.tools.CreateFunctionTool;
import ghidrassistmcp.tools.DisassembleAtTool;
import ghidrassistmcp.tools.GetBasicBlocksTool;
import ghidrassistmcp.tools.ImportFileTool;
import ghidrassistmcp.tools.OpenProgramTool;
import ghidrassistmcp.tools.ProjectFilesTool;
import ghidrassistmcp.tools.ExportProgramTool;
import ghidrassistmcp.tools.GetCodeTool;
import ghidrassistmcp.tools.GetCurrentAddressTool;
import ghidrassistmcp.tools.GetCurrentFunctionTool;
import ghidrassistmcp.tools.GetEntryPointsTool;
import ghidrassistmcp.tools.GetFunctionInfoTool;
import ghidrassistmcp.tools.GetFunctionSignatureTool;
import ghidrassistmcp.tools.GetFunctionStackLayoutTool;
import ghidrassistmcp.tools.GetFunctionStatisticsTool;
import ghidrassistmcp.tools.GetHexdumpTool;
import ghidrassistmcp.tools.GetTaskStatusTool;
import ghidrassistmcp.tools.GhidraScriptsTool;
import ghidrassistmcp.tools.ListDataTool;
import ghidrassistmcp.tools.ListExportsTool;
import ghidrassistmcp.tools.ListProgramsTool;
import ghidrassistmcp.tools.ListFunctionsTool;
import ghidrassistmcp.tools.ListImportsTool;
import ghidrassistmcp.tools.ListNamespacesTool;
import ghidrassistmcp.tools.ListRelocationsTool;
import ghidrassistmcp.tools.ListSegmentsTool;
import ghidrassistmcp.tools.CreateMemoryBlockTool;
import ghidrassistmcp.tools.ListStringsTool;
import ghidrassistmcp.tools.ListTasksTool;
import ghidrassistmcp.tools.ProgramInfoTool;
import ghidrassistmcp.tools.RenameSymbolBatchTool;
import ghidrassistmcp.tools.RenameSymbolTool;
import ghidrassistmcp.tools.PatchBytesTool;
import ghidrassistmcp.tools.SearchBytesTool;
import ghidrassistmcp.tools.SearchFunctionsByNameTool;
import ghidrassistmcp.tools.SearchStringsTool;
import ghidrassistmcp.tools.StructTool;
import ghidrassistmcp.tools.TypesTool;
import ghidrassistmcp.tools.VariablesTool;
import ghidrassistmcp.tools.XrefsTool;
import ghidrassistmcp.tools.WriteBytesTool;
import ghidrassistmcp.tools.ClearCodeRangesTool;
import ghidrassistmcp.tools.SetRegisterContextTool;
import ghidrassistmcp.tools.RunScriptTool;
import ghidrassistmcp.tools.PatchInstructionTool;
import ghidrassistmcp.tools.ExportFunctionSignaturesTool;
import ghidrassistmcp.tools.FunctionByteMatcherTool;
import ghidrassistmcp.tools.StringAnchorMatcherTool;
import ghidrassistmcp.tools.BulkTransferLabelsTool;
import ghidrassistmcp.tools.CreateFunctionsAtAddressesTool;
import ghidrassistmcp.tools.BulkRegionTransferTool;
import ghidrassistmcp.tools.GetDataTypeTool;
import ghidrassistmcp.tools.DeleteDataTypeTool;
import ghidrassistmcp.tools.ListDataTypesTool;
import ghidrassistmcp.tools.SetFunctionPrototypeTool;
import ghidrassistmcp.tools.SetLocalVariableTypeTool;
import ghidrassistmcp.tools.SetDataTypeTool;
import ghidrassistmcp.tools.SetCommentTool;
import ghidrassistmcp.tools.GetCallGraphTool;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * Implementation of the MCP backend that manages tools and program state.
 * Works with the singleton GhidrAssistMCPManager to support multiple CodeBrowser windows.
 */
public class GhidrAssistMCPBackend implements McpBackend {

    private final Map<String, McpTool> tools = new ConcurrentHashMap<>();
    private final Map<String, String> toolAliases = new ConcurrentHashMap<>();
    private final Map<String, Boolean> toolEnabledStates = new ConcurrentHashMap<>();
    private final List<McpEventListener> eventListeners = new CopyOnWriteArrayList<>();
    private volatile GhidrAssistMCPManager manager;
    private volatile boolean asyncExecutionEnabled = true;
    private final McpTaskManager taskManager;
    private final McpResourceRegistry resourceRegistry;
    private final McpPromptRegistry promptRegistry;
    private final McpCache cache;
    private final DecompilerService decompilerService;
    
    public GhidrAssistMCPBackend() {
        this.decompilerService = new DecompilerService(program -> {
            if (manager == null) {
                return null;
            }
            return manager.getToolForProgram(program);
        });

        // Initialize task manager for async operations
        this.taskManager = new McpTaskManager();

        // Initialize resource registry
        this.resourceRegistry = new McpResourceRegistry();
        registerBuiltinResources();

        // Initialize prompt registry
        this.promptRegistry = new McpPromptRegistry();
        registerBuiltinPrompts();

        // Initialize result cache
        this.cache = new McpCache();

        // Register built-in tools (renamed: list_* → get_*, etc.)
        registerTool(new ProgramInfoTool());         // get_binary_info
        registerTool(new ListProgramsTool());        // list_binaries
        registerTool(new ListFunctionsTool());       // get_functions
        registerTool(new GetFunctionInfoTool());     // analyze_function
        registerTool(new GetFunctionSignatureTool());
        registerTool(new ListSegmentsTool());        // get_segments
        registerTool(new ListImportsTool());         // get_imports
        registerTool(new ListExportsTool());         // get_exports
        registerTool(new ListStringsTool());         // get_strings
        registerTool(new ListDataTool());            // get_data_vars
        registerTool(new ListNamespacesTool());       // get_namespaces
        registerTool(new ListRelocationsTool());     // get_relocations
        registerTool(new GetCurrentAddressTool());
        registerTool(new GetCurrentFunctionTool());
        registerTool(new GetHexdumpTool());          // get_data_at

        // Register consolidated tools (replace individual tools)
        registerTool(new CommentsTool());            // comments (replaces set_comment)
        registerTool(new VariablesTool(decompilerService)); // variables (replaces set_local_variable_type + set_function_prototype)
        registerTool(new TypesTool());               // types (replaces get/set/delete/list_data_type[s])
        registerTool(new XrefsTool());               // xrefs (absorbs get_call_graph)
        registerTool(new StructTool(decompilerService)); // struct (advanced struct operations)

        // Register standalone tools
        registerTool(new GetCodeTool(decompilerService));
        registerTool(new GetBasicBlocksTool());
        registerTool(new RenameSymbolTool(decompilerService));
        registerTool(new RenameSymbolBatchTool(decompilerService)); // batch_rename
        registerTool(new SearchBytesTool());
        registerTool(new BookmarksTool());           // bookmarks (actions: list/set/remove)
        registerTool(new ClassTool());               // classes

        // Register new tools (Phase 4 — feature parity)
        registerTool(new SearchFunctionsByNameTool());
        registerTool(new GetFunctionStatisticsTool());
        registerTool(new GetFunctionStackLayoutTool());
        registerTool(new SearchStringsTool());
        registerTool(new CreateDataVarTool());
        registerTool(new CreateFunctionTool());       // create_function
        registerTool(new DisassembleAtTool());         // disassemble_at
        registerTool(new GetEntryPointsTool());

        // Register project-level tools
        registerTool(new OpenProgramTool());          // open_program: open/list project files in CodeBrowser
        registerTool(new CloseProgramTool());         // close_program: close open programs in CodeBrowser
        registerTool(new ProjectFilesTool());         // project_files: list/delete project files and folders
        registerTool(new ghidrassistmcp.tools.SaveProgramTool());
        registerTool(new ghidrassistmcp.tools.ProjectRepositoryTool());
        registerTool(new ghidrassistmcp.tools.QueryAddressContextBatchTool());
        registerTool(new ghidrassistmcp.tools.SearchSymbolsBatchTool());
        registerTool(new ghidrassistmcp.tools.ReadMemoryBatchTool());
        registerTool(new ghidrassistmcp.tools.ReadMemoryTableTool());
        registerTool(new ghidrassistmcp.tools.XrefsBatchTool());
        registerTool(new ghidrassistmcp.tools.FunctionInventoryTool());
        registerTool(new ghidrassistmcp.tools.ScanInstructionsTool());
        registerTool(new ghidrassistmcp.tools.ScanFunctionCandidatesTool());
        registerTool(new ghidrassistmcp.tools.GetRegisterContextTool());
        for (McpTool bsimTool : ghidrassistmcp.bsim.BsimTool.tools()) registerTool(bsimTool);
        for (McpTool nativeTool : ghidrassistmcp.nativeapi.NativeAnalysisTools.tools()) registerTool(nativeTool);
        for (String name : List.of("vt_sessions", "vt_session", "vt_correlators", "vt_correlate", "vt_matches",
                "vt_review_matches", "vt_add_matches", "vt_markup", "vt_apply_markup", "vt_unapply_markup"))
            registerTool(new ghidrassistmcp.vt.VTTool(name));
        registerTool(new ghidrassistmcp.tools.SaveProjectSessionTool());
        registerTool(new AssembleCodeTool());         // assemble_code: assemble instructions and optionally patch bytes
        registerTool(new PatchBytesTool());           // patch_bytes: write patched bytes into program memory

        // Register Auto Analysis tools
        registerTool(new AnalysisOptionsTool());      // analysis_options: list/set/reset/save/apply presets
        registerTool(new AnalyzeProgramTool());       // analyze_program: run Auto Analysis
        registerTool(new AnalysisControlTool());      // analysis_control: status/cancel queued analysis

        // Register tools that are disabled by default (security-sensitive)
        registerTool(new ImportFileTool());
        toolEnabledStates.put("import_file", false); // disabled by default: exposes host file-system read access
        registerTool(new GhidraScriptsTool());
        toolEnabledStates.put("scripts", false); // disabled by default: creates/deletes/runs host-side Ghidra scripts
        registerTool(new ExportProgramTool());
        toolEnabledStates.put("export_program", false); // disabled by default: writes files to host filesystem

        // Register async task management tools
        registerTool(new GetTaskStatusTool());
        registerTool(new CancelTaskTool());
        registerTool(new ListTasksTool());

        // Custom tools: memory/code manipulation, scripting, assembly
        registerTool(new CreateMemoryBlockTool());
        registerTool(new WriteBytesTool());
        registerTool(new ClearCodeRangesTool());
        registerTool(new SetRegisterContextTool());
        registerTool(new RunScriptTool());
        registerTool(new PatchInstructionTool());

        // Cross-binary analysis tools: function matching and label transfer
        registerTool(new ExportFunctionSignaturesTool());
        registerTool(new FunctionByteMatcherTool());
        registerTool(new StringAnchorMatcherTool());
        registerTool(new BulkTransferLabelsTool());
        registerTool(new CreateFunctionsAtAddressesTool());
        registerTool(new BulkRegionTransferTool());

        // Keep existing client schemas for tools consolidated upstream.
        registerTool(new GetDataTypeTool());
        registerTool(new DeleteDataTypeTool());
        registerTool(new ListDataTypesTool());
        registerTool(new SetFunctionPrototypeTool());
        registerTool(new SetLocalVariableTypeTool(decompilerService));
        registerTool(new SetDataTypeTool());
        registerTool(new SetCommentTool());
        registerTool(new GetCallGraphTool());

        // Public names used by existing clients and saved settings.
        registerAlias("get_program_info", "get_binary_info");
        registerAlias("list_functions", "get_functions");
        registerAlias("get_function_info", "analyze_function");
        registerAlias("list_segments", "get_segments");
        registerAlias("list_imports", "get_imports");
        registerAlias("list_exports", "get_exports");
        registerAlias("list_strings", "get_strings");
        registerAlias("get_hexdump", "get_data_at");
        registerAlias("list_data", "get_data_vars");
        registerAlias("list_namespaces", "get_namespaces");
        registerAlias("list_programs", "list_binaries");
        registerAlias("class", "classes");
        registerAlias("rename_symbol_batch", "batch_rename");
        registerAlias("list_relocations", "get_relocations");

        Msg.info(this, "GhidrAssistMCP Backend initialized with " + tools.size() + " tools");
    }
    
    @Override
    public void registerTool(McpTool tool) {
        toolAliases.remove(tool.getName());
        tools.put(tool.getName(), tool);
        toolAliases.forEach((alias, target) -> {
            if (target.equals(tool.getName())) {
                tools.put(alias, new ToolAlias(alias, tool));
            }
        });
        // Tools are enabled by default when registered
        toolEnabledStates.put(tool.getName(), true);
        Msg.info(this, "Registered MCP tool: " + tool.getName());
    }
    
    @Override
    public void unregisterTool(String toolName) {
        McpTool removed = tools.remove(toolName);
        toolAliases.remove(toolName);
        List<String> aliases = toolAliases.entrySet().stream()
            .filter(entry -> entry.getValue().equals(toolName))
            .map(Map.Entry::getKey).toList();
        aliases.forEach(alias -> {
            tools.remove(alias);
            toolAliases.remove(alias);
        });
        toolEnabledStates.remove(toolName);
        if (removed != null) {
            Msg.info(this, "Unregistered MCP tool: " + toolName);
        }
    }
    
    @Override
    public List<McpSchema.Tool> getAvailableTools() {
        List<McpSchema.Tool> toolList = new ArrayList<>();
        for (McpTool tool : tools.values()) {
            // Only include enabled tools in the available tools list
            if (isToolEnabled(tool.getName())) {
                // Augment the schema with program_name parameter for multi-program support
                McpSchema.JsonSchema augmentedSchema = augmentSchemaWithProgramName(tool.getInputSchema());

                // Build tool annotations based on McpTool interface methods
                McpSchema.ToolAnnotations annotations = new McpSchema.ToolAnnotations(
                    null,  // title - will use tool name
                    tool.isReadOnly(),
                    tool.isDestructive(),
                    tool.isIdempotent(),
                    tool.isOpenWorld(),
                    null   // returnDirect
                );

                toolList.add(McpSchema.Tool.builder()
                    .name(tool.getName())
                    .title(tool.getName())
                    .description(tool.getDescription())
                    .inputSchema(augmentedSchema)
                    .annotations(annotations)
                    .build());
            }
        }
        // Sort tools alphabetically by name for consistent ordering
        toolList.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return toolList;
    }

    /**
     * Augment a tool's input schema with the universal 'program_name' parameter.
     * This allows all tools to optionally target a specific open program.
     */
    private McpSchema.JsonSchema augmentSchemaWithProgramName(McpSchema.JsonSchema originalSchema) {
        // Create the program_name property schema
        Map<String, Object> programNameSchema = new HashMap<>();
        programNameSchema.put("type", "string");
        programNameSchema.put("description", "Optional exact open program name, project path or URL. Missing/ambiguous selectors fail. " +
            "Use program_id for version-specific identity. If neither selector is specified, uses the active program.");

        if (originalSchema == null) {
            // Create a schema with just program_name
            Map<String, Object> props = new HashMap<>();
            props.put("program_name", programNameSchema);
            props.put("program_id", Map.of("type", "string", "description", "Exact program_id returned by list_binaries or runtime diagnostics"));
            return new McpSchema.JsonSchema("object", props, List.of(), null, null, null);
        }

        // Get original properties or empty map
        Map<String, Object> originalProps = originalSchema.properties();
        Map<String, Object> newProps;

        if (originalProps != null) {
            newProps = new HashMap<>(originalProps);
        } else {
            newProps = new HashMap<>();
        }

        // Add program_name parameter
        newProps.put("program_name", programNameSchema);
        newProps.put("program_id", Map.of("type", "string", "description", "Exact program_id returned by list_binaries or runtime diagnostics"));

        // Return new schema with augmented properties
        return new McpSchema.JsonSchema(
            originalSchema.type(),
            newProps,
            originalSchema.required(),
            originalSchema.additionalProperties(),
            originalSchema.defs(),
            originalSchema.definitions()
        );
    }
    
    @Override
    public McpSchema.CallToolResult callTool(String toolName, Map<String, Object> arguments) {
        McpTool tool = tools.get(toolName);
        if (tool == null) {
            Msg.warn(this, "Tool not found: " + toolName);
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Tool not found: " + toolName)
                .build();
        }

        // Check if tool is enabled
        if (!isToolEnabled(toolName)) {
            Msg.warn(this, "Tool is disabled: " + toolName);
            return McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Tool is disabled: " + toolName)
                .build();
        }

        try {
            // Freeze project selection before a task can wait behind another worker.
            if (List.of("project_files", "project_repository", "save_program", "save_project_session").contains(toolName)
                    || toolName.startsWith("vt_")) {
                var project = getProject();
                arguments = new HashMap<>(arguments);
                arguments.put("__project_identity", project == null ? "<none>" : project.getProjectLocator().toString());
            }
            // Notify listeners of the request
            notifyToolRequest(toolName, arguments);

            Msg.info(this, "Executing tool: " + toolName);

            // Resolve the target program - check if program_name is specified
            Program targetProgram = resolveTargetProgram(arguments);

            // Check cache for cacheable tools
            CacheSnapshot cacheSnapshot = captureCacheSnapshot(tool, toolName, arguments, targetProgram);
            if (cacheSnapshot != null) {
                McpSchema.CallToolResult cachedResult = cache.get(cacheSnapshot.key(), targetProgram);
                if (cachedResult != null) {
                    Msg.info(this, "Cache hit for tool: " + toolName);
                    cachedResult = addActiveContextToResult(cachedResult,
                        resolveResultProgramContext(tool, arguments, targetProgram));
                    notifyToolResponse(toolName, cachedResult);
                    return cachedResult;
                }
            }

            // Check if this is a long-running tool that should be executed asynchronously
            if (tool.isLongRunning() && asyncExecutionEnabled) {
                return executeToolAsync(tool, toolName, arguments, targetProgram, cacheSnapshot);
            }

            // Execute synchronously for normal tools
            McpSchema.CallToolResult result = executeGuarded(tool, arguments, targetProgram, null);

            cacheSuccessfulResult(tool, toolName, arguments, targetProgram, cacheSnapshot, result, null);

            // Add active context information to help LLM understand which binary is in focus
            result = addActiveContextToResult(result,
                resolveResultProgramContext(tool, arguments, targetProgram));

            // Notify listeners of the response
            notifyToolResponse(toolName, result);

            return result;
        } catch (Exception e) {
            Msg.error(this, "Error executing tool " + toolName, e);
            McpSchema.CallToolResult errorResult = McpSchema.CallToolResult.builder()
                .isError(true)
                .addTextContent("Error executing tool " + toolName + ": " + e.getMessage())
                .build();

            // Notify listeners of the error response
            notifyToolResponse(toolName, errorResult);

            return errorResult;
        }
    }

    /**
     * Execute a long-running tool asynchronously and return a task ID.
     */
    private McpSchema.CallToolResult executeToolAsync(McpTool tool, String toolName,
                                                       Map<String, Object> arguments, Program targetProgram,
                                                       CacheSnapshot cacheSnapshot) {
        McpTask task = submitTask(toolName, arguments, targetProgram, taskContext -> {
            try {
                McpSchema.CallToolResult result =
                    executeGuarded(tool, arguments, targetProgram, taskContext);
                cacheSuccessfulResult(tool, toolName, arguments, targetProgram, cacheSnapshot, result, taskContext);
                // Store the raw result, but retain context in the response shown to listeners.
                // get_task_status decorates the stored result once using this task's snapshot.
                notifyToolResponse(toolName,
                    addActiveContextToResult(result, taskContext.getProgramContext()));
                return result;
            } catch (Exception e) {
                Msg.error(this, "Async tool execution failed: " + toolName, e);
                throw new RuntimeException(e);
            }
        });

        // Return task information immediately
        return McpSchema.CallToolResult.builder()
            .addTextContent("Task submitted for async execution.\n\n" +
                "Task ID: " + task.getTaskId() + "\n" +
                "Tool: " + toolName + "\n" +
                "Status: " + task.getStatus() + "\n\n" +
                "Use get_task_status with this task_id to check progress and retrieve results.\n" +
                "Use cancel_task to cancel if needed.")
            .build();
    }

    private record CacheSnapshot(String key, String programName, long modificationNumber) {}

    private CacheSnapshot captureCacheSnapshot(McpTool tool, String toolName,
            Map<String, Object> arguments, Program program) {
        if (!tool.isCacheable() || program == null || program.isClosed()) return null;
        return new CacheSnapshot(cache.generateKey(toolName, arguments, ProgramIdentity.id(program),
            tool.getCacheDiscriminator(arguments, program, this)), program.getName(), program.getModificationNumber());
    }

    /** Both execution paths cache raw successes only, with the revision captured before execution. */
    private void cacheSuccessfulResult(McpTool tool, String toolName, Map<String, Object> arguments,
            Program program, CacheSnapshot before, McpSchema.CallToolResult result, McpTask task) {
        if (before == null || result == null || Boolean.TRUE.equals(result.isError())
                || Thread.currentThread().isInterrupted()
                || task != null && task.getStatus() == McpTask.Status.CANCEL_REQUESTED) return;
        CacheSnapshot after = captureCacheSnapshot(tool, toolName, arguments, program);
        if (before.equals(after)) {
            cache.put(before.key(), result, before.programName(), before.modificationNumber());
        }
    }

    /**
     * Get the task manager for async operations.
     */
    public McpTaskManager getTaskManager() {
        return taskManager;
    }

    /**
     * Submit an async task while retaining a stable snapshot of its target program.
     */
    public McpTask submitTask(String toolName, Map<String, Object> arguments,
                              Program targetProgram,
                              Function<McpTask, McpSchema.CallToolResult> taskExecutor) {
        Object consumer = new Object();
        if (targetProgram != null && !targetProgram.addConsumer(consumer))
            throw new IllegalStateException("Target program closed before task submission");
        return taskManager.submitTask(toolName, arguments,
            captureProgramContext(targetProgram), taskExecutor, () -> {
                if (targetProgram != null && !targetProgram.isClosed() && targetProgram.isUsedBy(consumer))
                    targetProgram.release(consumer);
            });
    }

    /**
     * Capture program identity without retaining a live Program reference in the task manager.
     */
    public McpProgramContext captureProgramContext(Program program) {
        if (program == null) {
            return McpProgramContext.empty();
        }

        DomainFile domainFile = program.getDomainFile();
        String projectPath = domainFile != null ? domainFile.getPathname() : null;
        String fileId = domainFile != null ? domainFile.getFileID() : null;
        return new McpProgramContext(program.getName(), projectPath, fileId);
    }

    /**
     * Get the resource registry.
     */
    public McpResourceRegistry getResourceRegistry() {
        return resourceRegistry;
    }

    /**
     * Register built-in MCP resources.
     */
    private void registerBuiltinResources() {
        resourceRegistry.registerResource(new ProgramInfoResource());
        resourceRegistry.registerResource(new FunctionListResource());
        resourceRegistry.registerResource(new StringsResource());
        resourceRegistry.registerResource(new ImportsResource());
        resourceRegistry.registerResource(new ExportsResource());
        resourceRegistry.registerResource(new ghidrassistmcp.resources.SegmentsResource());
        resourceRegistry.registerResource(new ghidrassistmcp.resources.RuntimeCapabilitiesResource(() -> this));
        Msg.info(this, "Registered " + resourceRegistry.getResourceCount() + " MCP resources");
    }

    /**
     * Register built-in MCP prompts.
     */
    private void registerBuiltinPrompts() {
        promptRegistry.registerPrompt(new AnalyzeFunctionPrompt(decompilerService));
        promptRegistry.registerPrompt(new IdentifyVulnerabilityPrompt(decompilerService));
        promptRegistry.registerPrompt(new DocumentFunctionPrompt(decompilerService));
        promptRegistry.registerPrompt(new TraceDataFlowPrompt(decompilerService));
        promptRegistry.registerPrompt(new TraceNetworkDataPrompt(decompilerService));
        promptRegistry.registerPrompt(
            new ghidrassistmcp.prompts.CompareFunctionsPrompt(decompilerService));
        promptRegistry.registerPrompt(new ghidrassistmcp.prompts.ReverseEngineerStructPrompt());
        Msg.info(this, "Registered " + promptRegistry.getPromptCount() + " MCP prompts");
    }

    /**
     * Get the prompt registry.
     */
    public McpPromptRegistry getPromptRegistry() {
        return promptRegistry;
    }

    /**
     * Get available prompts for the MCP SDK.
     */
    public List<McpPrompt> getAvailablePrompts() {
        return promptRegistry.getAllPrompts();
    }

    /**
     * Get the result cache.
     */
    public McpCache getCache() {
        return cache;
    }

    /**
     * Get cache statistics summary.
     */
    public String getCacheStats() {
        return cache.getStats();
    }

    /**
     * Clear the cache (e.g., when program is significantly modified).
     */
    public void clearCache() {
        cache.clear();
    }

    /**
     * Read a resource by URI.
     *
     * @param uri The resource URI
     * @return The resource content
     */
    public String readResource(String uri) {
        Program program = getCurrentProgram();
        return resourceRegistry.readResource(uri, program);
    }

    /**
     * Get available resources for the MCP SDK.
     */
    public List<McpResource> getAvailableResources() {
        return resourceRegistry.getAllResources();
    }

    @Override
    public void onProgramActivated(Program program) {
        // Program activation is now handled dynamically - no caching needed
        if (program != null) {
            Msg.info(this, "Program activated: " + program.getName());
            // Notify listeners for logging purposes
            notifySessionEvent("Program activated: " + program.getName());
        }
    }

    @Override
    public void onProgramDeactivated(Program program) {
        // Program deactivation is now handled dynamically - no state clearing needed
        if (program != null) {
            Msg.info(this, "Program deactivated: " + program.getName());
        }
    }
    
    @Override
    public McpSchema.Implementation getServerInfo() {
        return new McpSchema.Implementation("ghidrassistmcp", "1.0.0");
    }
    
    @Override
    public McpSchema.ServerCapabilities getCapabilities() {
        return McpSchema.ServerCapabilities.builder()
            .tools(true)
            .resources(false, false)  // subscribe=false, listChanged=false
            .prompts(false)           // listChanged=false
            .build();
    }
    
    /**
     * Resolve the target program based on arguments.
     * If 'program_name' is specified, look up that program across ALL open tools.
     * Otherwise, return the currently active program.
     *
     * @param arguments The tool arguments that may contain 'program_name'
     * @return The resolved program to operate on
     */
    private Program resolveTargetProgram(Map<String, Object> arguments) {
        if (!arguments.containsKey("program_name") && !arguments.containsKey("program_id")) return getCurrentProgram();
        var programs = new java.util.LinkedHashSet<Program>(getAllOpenPrograms());
        if (getCurrentProgram() != null) programs.add(getCurrentProgram());
        Program result = null;
        for (String field : List.of("program_name", "program_id")) {
            if (!arguments.containsKey(field)) continue;
            if (!(arguments.get(field) instanceof String selector) || selector.isBlank())
                throw new IllegalArgumentException(field + " must be a nonblank string");
            Program selected = ProgramIdentity.resolve(selector, programs);
            if (result != null && selected != result) throw new IllegalArgumentException("program_name and program_id select different programs");
            result = selected;
        }
        return result;
    }

    /**
     * Get the currently active program from the manager.
     * This queries ALL registered tools for the currently active program.
     */
    public Program getCurrentProgram() {
        if (manager != null) {
            return manager.getCurrentProgram();
        }
        return null;
    }

    /**
     * Get all open programs from ALL registered tools.
     */
    public List<Program> getAllOpenPrograms() {
        if (manager != null) {
            return manager.getAllOpenPrograms();
        }
        return new ArrayList<>();
    }
    
    /**
     * Add an event listener for MCP operations.
     */
    public void addEventListener(McpEventListener listener) {
        if (listener != null) {
            eventListeners.add(listener);
            Msg.info(this, "Added MCP event listener: " + listener.getClass().getSimpleName() + " (total listeners: " + eventListeners.size() + ")");
        }
    }
    
    /**
     * Remove an event listener.
     */
    public void removeEventListener(McpEventListener listener) {
        if (listener != null) {
            eventListeners.remove(listener);
            Msg.info(this, "Removed MCP event listener: " + listener.getClass().getSimpleName());
        }
    }
    
    /**
     * Set the manager reference for multi-tool program discovery.
     */
    public void setManager(GhidrAssistMCPManager manager) {
        this.manager = manager;
        Msg.info(this, "Manager reference set for multi-tool support");
    }

    /**
     * Get the currently active plugin instance for UI context access.
     * This allows tools to access current address, current function, etc.
     *
     * @return The active plugin instance, or null if none is active
     */
    public GhidrAssistMCPPlugin getActivePlugin() {
        if (manager != null) {
            return manager.getActivePlugin();
        }
        return null;
    }
    
    /**
     * Notify listeners of a tool request.
     */
    private void notifyToolRequest(String toolName, Map<String, Object> arguments) {
        String params = arguments != null ? arguments.toString() : "{}";
        if (params.length() > 60) {
            params = params.substring(0, 57) + "...";
        }
        
        Msg.info(this, "Notifying " + eventListeners.size() + " listeners of tool request: " + toolName);
        
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onToolRequest(toolName, params);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of tool request", e);
            }
        }
    }
    
    /**
     * Notify listeners of a tool response.
     */
    private void notifyToolResponse(String toolName, McpSchema.CallToolResult result) {
        String response = "Empty response";
        if (result != null && !result.content().isEmpty()) {
            var firstContent = result.content().get(0);
            if (firstContent instanceof McpSchema.TextContent) {
                response = ((McpSchema.TextContent) firstContent).text();
                if (response.length() > 60) {
                    response = response.substring(0, 57) + "...";
                }
            }
        }
        
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onToolResponse(toolName, response);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of tool response", e);
            }
        }
    }
    
    /**
     * Notify listeners of a session event.
     */
    private void notifySessionEvent(String event) {
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onSessionEvent(event);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of session event", e);
            }
        }
    }
    
    /**
     * Notify listeners of a general log message.
     */
    @SuppressWarnings("unused")
    private void notifyLogMessage(String message) {
        for (McpEventListener listener : eventListeners) {
            try {
                listener.onLogMessage(message);
            } catch (Exception e) {
                Msg.error(this, "Error notifying listener of log message", e);
            }
        }
    }
    
    /**
     * Resolve the context that belongs to a response. Completed task results retain the target
     * from their original invocation rather than inheriting the program active while polling.
     */
    private McpProgramContext resolveResultProgramContext(McpTool tool,
                                                           Map<String, Object> arguments,
                                                           Program targetProgram) {
        if (tool instanceof GetTaskStatusTool) {
            Object taskId = arguments.get("task_id");
            if (taskId instanceof String id) {
                McpTask task = taskManager.getTask(id);
                if (task != null) {
                    return task.getProgramContext();
                }
            }
        }
        return captureProgramContext(targetProgram);
    }

    /**
     * Add active context information to tool results to help LLM understand which binary is in focus.
     * This prepends context metadata to the first text content in the result.
     */
    private McpSchema.CallToolResult addActiveContextToResult(McpSchema.CallToolResult result,
                                                               McpProgramContext targetProgram) {
        if (result == null || result.content() == null || result.content().isEmpty()) {
            return result;
        }

        // Build context information
        StringBuilder contextInfo = new StringBuilder();

        // Get the current active program from manager
        McpProgramContext activeProgram = captureProgramContext(getCurrentProgram());

        // Add context header
        contextInfo.append("[Context] ");

        if (targetProgram.hasProgram()) {
            contextInfo.append("Operating on: ").append(targetProgram.displayName());

            // If active program is different, mention it
            if (activeProgram.hasProgram() &&
                    !targetProgram.identifiesSameProgram(activeProgram)) {
                contextInfo.append(" | Active window: ").append(activeProgram.displayName());
            }
        } else if (activeProgram.hasProgram()) {
            contextInfo.append("Active window: ").append(activeProgram.displayName());
        } else {
            contextInfo.append("No program currently active");
        }

        // Add available programs count if multiple are open
        if (manager != null) {
            List<Program> allPrograms = manager.getAllOpenPrograms();
            if (allPrograms.size() > 1) {
                contextInfo.append(" | Total open programs: ").append(allPrograms.size());
            }
        }

        contextInfo.append("\n\n");

        // Prepend context to the first text content
        var firstContent = result.content().get(0);
        if (firstContent instanceof McpSchema.TextContent) {
            String originalText = ((McpSchema.TextContent) firstContent).text();
            String enhancedText = contextInfo.toString() + originalText;

            // Build new result with enhanced content
            McpSchema.CallToolResult.Builder builder = McpSchema.CallToolResult.builder()
                .isError(result.isError())
                .addTextContent(enhancedText);
            if (result.structuredContent() != null) builder.structuredContent(result.structuredContent());
            if (result.meta() != null) builder.meta(result.meta());

            // Add remaining content items if any
            for (int i = 1; i < result.content().size(); i++) {
                var content = result.content().get(i);
                builder.addContent(content);
            }

            return builder.build();
        }

        return result;
    }

    /**
     * Set whether async execution is enabled for long-running tools.
     */
    public void setAsyncExecutionEnabled(boolean enabled) {
        this.asyncExecutionEnabled = enabled;
        Msg.info(this, "Async tool execution " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * Check whether async execution is enabled for long-running tools.
     */
    public boolean isAsyncExecutionEnabled() {
        return asyncExecutionEnabled;
    }

    /**
     * Set the enabled state of a tool.
     */
    public void setToolEnabled(String toolName, boolean enabled) {
        if (tools.containsKey(toolName)) {
            toolEnabledStates.put(toolAliases.getOrDefault(toolName, toolName), enabled);
            Msg.info(this, "Tool " + toolName + " " + (enabled ? "enabled" : "disabled"));
        }
    }
    
    /**
     * Get the enabled state of a tool.
     */
    public boolean isToolEnabled(String toolName) {
        return toolEnabledStates.getOrDefault(toolAliases.getOrDefault(toolName, toolName), true);
    }
    
    /**
     * Get all tool enabled states.
     */
    public Map<String, Boolean> getToolEnabledStates() {
        Map<String, Boolean> states = new HashMap<>();
        tools.keySet().forEach(name -> states.put(name, isToolEnabled(name)));
        return states;
    }
    
    /**
     * Update multiple tool enabled states at once.
     */
    public void updateToolEnabledStates(Map<String, Boolean> newStates) {
        // Apply changed values as a batch so a legacy preference or a single UI
        // checkbox updates the shared state, regardless of map iteration order.
        Map<String, Boolean> changes = new HashMap<>();
        for (Map.Entry<String, Boolean> entry : newStates.entrySet()) {
            String toolName = entry.getKey();
            if (tools.containsKey(toolName) && entry.getValue() != null &&
                    entry.getValue() != isToolEnabled(toolName)) {
                changes.put(toolAliases.getOrDefault(toolName, toolName), entry.getValue());
            }
        }
        changes.forEach(this::setToolEnabled);
        Msg.info(this, "Updated enabled states for " + newStates.size() + " tools");
    }

    private McpSchema.CallToolResult executeGuarded(McpTool tool, Map<String,Object> arguments,
            Program program, McpTask task) throws InterruptedException {
        // BSim invokes its handlers on a separate worker, which acquires this guard there.
        boolean write = !tool.isReadOnly() && !tool.getName().startsWith("bsim_");
        if (write) McpMutationGuard.LOCK.lockInterruptibly();
        try { return task == null ? tool.execute(arguments, program, this) : tool.execute(arguments, program, this, task); }
        finally { if (write) McpMutationGuard.LOCK.unlock(); }
    }

    /** Project context is supplied by the runtime, independent of CodeBrowser. */
    public ghidra.framework.model.Project getProject() {
        var activeTool = manager == null ? null : manager.getActiveTool();
        return activeTool == null ? ghidra.framework.main.AppInfo.getActiveProject() : activeTool.getProject();
    }

    public boolean isHeadlessSession() { return false; }

    public Program openProjectProgram(DomainFile file, int version, ghidra.util.task.TaskMonitor monitor) throws Exception {
        throw new UnsupportedOperationException("This runtime uses the GUI ProgramManager");
    }

    public boolean closeProjectProgram(Program program, boolean discard) throws Exception {
        throw new UnsupportedOperationException("This runtime uses the GUI ProgramManager");
    }

    private void registerAlias(String alias, String target) {
        McpTool delegate = tools.get(target);
        if (delegate == null || tools.containsKey(alias)) {
            throw new IllegalArgumentException("Invalid tool alias: " + alias + " -> " + target);
        }
        toolAliases.put(alias, target);
        tools.put(alias, new ToolAlias(alias, delegate));
    }
    
    /**
     * Get all tools (including disabled ones) for configuration purposes.
     */
    public List<McpSchema.Tool> getAllTools() {
        List<McpSchema.Tool> toolList = new ArrayList<>();
        for (McpTool tool : tools.values()) {
            toolList.add(McpSchema.Tool.builder()
                .name(tool.getName())
                .title(tool.getName())
                .description(tool.getDescription())
                .inputSchema(tool.getInputSchema())
                .build());
        }
        // Sort tools alphabetically by name for consistent ordering
        toolList.sort((a, b) -> a.name().compareToIgnoreCase(b.name()));
        return toolList;
    }
}
