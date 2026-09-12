/*
 * MCP tool for listing all open programs in Ghidra.
 */
package ghidrassistmcp.tools;

import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.ArrayList;

import ghidra.program.model.listing.Program;
import ghidrassistmcp.GhidrAssistMCPBackend;
import ghidrassistmcp.McpTool;
import ghidrassistmcp.ProgramIdentity;
import io.modelcontextprotocol.spec.McpSchema;

/**
 * MCP tool that lists all currently open programs in Ghidra.
 * This is essential for multi-program scenarios where the LLM needs to know
 * which programs are available and select the correct one for operations.
 */
public class ListProgramsTool implements McpTool {

    @Override public Map<String,Object> getOutputSchema() {
        Map<String,Object> row=new LinkedHashMap<>();
        for(String k:List.of("program_id","name","project_path","executable_path","format","language")) row.put(k,Map.of("type","string"));
        row.put("modification_number",Map.of("type","integer"));
        for(String k:List.of("executable_path","format")) row.put(k,Map.of("type",List.of("string","null")));
        for(String k:List.of("program_url","file_id","compiler")) row.put(k,Map.of("type",List.of("string","null")));
        row.put("version",Map.of("type",List.of("integer","null")));
        for(String k:List.of("active","dirty","changeable","read_only","can_save","busy")) row.put(k,Map.of("type",List.of("boolean","null")));
        row.put("collision",Map.of("type","boolean")); row.put("collision_count",Map.of("type","integer"));
        Map<String,Object> item=Map.of("type","object","properties",row,"required",new ArrayList<>(row.keySet()),"additionalProperties",false);
        Map<String,Object> props=new LinkedHashMap<>(); props.put("schema_version",Map.of("type","integer","const",1)); props.put("inventory_revision",Map.of("type","string")); props.put("offset",Map.of("type","integer","minimum",0)); props.put("limit",Map.of("type","integer","minimum",1)); props.put("total",Map.of("type","integer","minimum",0)); props.put("programs",Map.of("type","array","items",item)); props.put("next_cursor",Map.of("type",List.of("string","null"))); props.put("exact_program_id_guidance",Map.of("type","string")); props.put("error",Map.of("type","string")); props.put("restart_required",Map.of("type","boolean")); props.put("message",Map.of("type","string"));
        List<String> success=List.of("schema_version","inventory_revision","offset","limit","total","programs","next_cursor","exact_program_id_guidance");
        Map<String,Object> ok=Map.of("type","object","properties",props,"required",success,"additionalProperties",false);
        Map<String,Object> err=Map.of("type","object","properties",props,"required",List.of("schema_version","error","message"),"additionalProperties",false);
        return Map.of("type", "object", "oneOf",List.of(ok,err));
    }

    @Override
    public String getName() {
        return "list_binaries";
    }

    @Override
    public String getDescription() {
        return "List open binaries in a bounded deterministic page. Use the exact program_id from a row for subsequent tools; names and paths can be ambiguous.";
    }

    @Override
    public McpSchema.JsonSchema getInputSchema() {
        return new McpSchema.JsonSchema("object", Map.of(
            "offset", new McpSchema.JsonSchema("integer", null, null, null, null, null),
            "limit", new McpSchema.JsonSchema("integer", null, null, null, null, null),
            "cursor", new McpSchema.JsonSchema("string", null, null, null, null, null)), List.of(), false, null, null);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram) {
        // This tool needs the backend to access all programs
        return ProjectToolSupport.result(Map.of("schema_version", 1, "error", "backend_unavailable",
            "message", "This tool requires backend context."), true);
    }

    @Override
    public McpSchema.CallToolResult execute(Map<String, Object> arguments, Program currentProgram, GhidrAssistMCPBackend backend) {
        if (backend == null) {
            return execute(arguments, currentProgram);
        }

        List<Program> programs = ProgramDiscoverySupport.unique(backend.getAllOpenPrograms());
        Program activeProgram = backend.getCurrentProgram();
        try {
            if (arguments.containsKey("cursor") && !(arguments.get("cursor") instanceof String))
                throw new IllegalArgumentException("cursor must be a string");
            long offsetLong=ProgramDiscoverySupport.integer(arguments.get("offset"),"offset",0), limitLong=ProgramDiscoverySupport.integer(arguments.get("limit"),"limit",ProgramDiscoverySupport.DEFAULT_LIMIT);
            if(offsetLong<0||limitLong<1||limitLong>ProgramDiscoverySupport.MAX_LIMIT||offsetLong>Integer.MAX_VALUE) throw new IllegalArgumentException("offset must be >= 0 and limit must be between 1 and 100");
            int offset=(int)offsetLong, limit=(int)limitLong;
            String rev=ProgramDiscoverySupport.revision(programs), cursor=arguments.get("cursor") instanceof String ? (String)arguments.get("cursor") : null;
            if(cursor!=null){String[] x=cursor.split(":",-1); if(x.length!=3||!x[0].equals("v1")) throw new IllegalArgumentException("cursor must have format v1:<revision>:<offset>"); if(!x[1].equals(rev)) return ProjectToolSupport.result(Map.of("schema_version",1,"error","inventory_changed","restart_required",true,"message","Open-program membership changed; restart from offset 0"),true); long cursorOffset=Long.parseLong(x[2]); if(cursorOffset<0||cursorOffset>Integer.MAX_VALUE) throw new IllegalArgumentException("cursor offset is out of range"); offset=(int)cursorOffset;}
            if(offset<0) throw new IllegalArgumentException("offset must be >= 0");
            int end=(int)Math.min((long)programs.size(),(long)offset+limit); List<Map<String,Object>> page=offset>=programs.size()?List.of():ProgramDiscoverySupport.rows(programs,offset,end); for(int i=0;i<page.size();i++) page.get(i).put("active",activeProgram!=null&&programs.get(offset+i)==activeProgram);
            Map<String,Object> out=new LinkedHashMap<>(); out.put("schema_version",1); out.put("inventory_revision",rev); out.put("offset",offset); out.put("limit",limit); out.put("total",programs.size()); out.put("programs",page); out.put("next_cursor",end<programs.size()?"v1:"+rev+":"+end:null); out.put("exact_program_id_guidance","Pass the row's exact program_id; do not select by display name or path when ambiguous.");
            // Bound the full result, including JSON text fallback, before context decoration.
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            while (mapper.writeValueAsBytes(ProjectToolSupport.result(out)).length > 18500) {
                if (page.size() <= 1) return ProjectToolSupport.result(Map.of("schema_version", 1,
                    "error", "program_row_too_large", "message", "A program row exceeds the discovery byte budget; inspect the selected program with get_binary_info."), true);
                page = new ArrayList<>(page.subList(0, page.size() - 1));
                out.put("programs", page);
                out.put("next_cursor", "v1:" + rev + ":" + ((long)offset + page.size()));
            }
            return ProjectToolSupport.result(out);
        } catch(Exception e) { return ProjectToolSupport.result(Map.of("schema_version",1,"error","invalid_arguments","message",String.valueOf(e.getMessage())),true); }
    }
}
