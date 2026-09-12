package ghidrassistmcp.nativeapi;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.task.TaskMonitor;
import ghidrassistmcp.*;
import ghidrassistmcp.tasks.*;
import io.modelcontextprotocol.spec.McpSchema;

/** Native type archives, C parsing, aligned program differences and Function ID queries. */
public final class NativeAnalysisTools {
    private static final ObjectMapper JSON=new ObjectMapper();
    private static final Object PARSER_LOCK=new Object();
    private NativeAnalysisTools(){}
    public static List<McpTool> tools(){return List.of(new ArchiveCatalog(),new ParseC(),new ImportTypes(),new Diff(),new FidCatalog(),new FidLookup());}
    static McpSchema.CallToolResult ok(Map<String,Object> value)throws Exception{return McpSchema.CallToolResult.builder().isError(false).structuredContent(value).addTextContent(JSON.writeValueAsString(value)).build();}
    static McpSchema.CallToolResult err(String message){return McpSchema.CallToolResult.builder().isError(true).addTextContent(String.valueOf(message)).build();}
    static Map<String,Object> prop(String type){return Map.of("type",type);}
    static Map<String,Object> array(String type,int max){return Map.of("type","array","items",prop(type),"maxItems",max);}
    static McpSchema.JsonSchema schema(Map<String,Object> props,String... required){return new McpSchema.JsonSchema("object",props,List.of(required),null,null,null);}
    static String required(Map<String,Object>a,String key){if(a.get(key) instanceof String s&&!s.isBlank())return s;throw new IllegalArgumentException(key+" is required");}
    static int number(Map<String,Object>a,String key,int fallback,int min,int max){if(!a.containsKey(key))return fallback;Object v=a.get(key);if(!(v instanceof Number n)||!Double.isFinite(n.doubleValue())||n.doubleValue()!=n.longValue()||n.longValue()<min||n.longValue()>max)throw new IllegalArgumentException(key+" must be an integer in "+min+".."+max);return n.intValue();}
    static List<String> strings(Map<String,Object>a,String key,int max,boolean required){if(!a.containsKey(key)&&!required)return List.of();if(!(a.get(key) instanceof List<?> raw)||raw.size()>max||(required&&raw.isEmpty()))throw new IllegalArgumentException(key+" must contain 1.."+max+" strings");List<String> out=new ArrayList<>();for(Object o:raw){if(!(o instanceof String s)||s.isBlank())throw new IllegalArgumentException(key+" must contain nonblank strings");out.add(s);}return out;}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static String fileHash(Path path,TaskMonitor monitor)throws Exception{var digest=MessageDigest.getInstance("SHA-256");try(var in=Files.newInputStream(path)){byte[] buffer=new byte[65536];int len;while((len=in.read(buffer))!=-1){monitor.checkCancelled();digest.update(buffer,0,len);}}return HexFormat.of().formatHex(digest.digest());}
    static Map<String,Object> typeRow(DataType d){Map<String,Object> row=new LinkedHashMap<>();row.put("path",d.getPathName());row.put("name",d.getName());row.put("category",d.getCategoryPath().getPath());row.put("length",d.getLength());row.put("id",d.getUniversalID()==null?null:d.getUniversalID().toString());return row;}
    private abstract static class NativeTool implements McpTool {
        @Override public boolean isLongRunning(){return true;}
        @Override public final McpSchema.CallToolResult execute(Map<String,Object>a,Program p){return execute(a,p,null,null);}
        @Override public final McpSchema.CallToolResult execute(Map<String,Object>a,Program p,GhidrAssistMCPBackend b){return execute(a,p,b,null);}
        @Override public final McpSchema.CallToolResult execute(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,McpTask task){
            TaskMonitor monitor=task==null?TaskMonitor.DUMMY:new McpTaskMonitor(task,0,100,getName());
            try{monitor.checkCancelled();return run(a,p,b,monitor);}catch(Exception e){return err(e.getClass().getSimpleName()+": "+e.getMessage());}
        }
        abstract McpSchema.CallToolResult run(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,TaskMonitor monitor)throws Exception;
    }
    static final class ArchiveCatalog extends NativeTool {
        public boolean isOpenWorld(){return true;}
        public String getName(){return "datatype_archive_catalog";}
        public String getDescription(){return "Read-only native GDT catalog with exact type paths, archive SHA-256 and paged metadata.";}
        public McpSchema.JsonSchema getInputSchema(){return schema(Map.of("path",prop("string"),"offset",prop("integer"),"limit",prop("integer")),"path");}
        McpSchema.CallToolResult run(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,TaskMonitor m)throws Exception{
            Path path=Path.of(required(a,"path")).toRealPath();int offset=number(a,"offset",0,0,Integer.MAX_VALUE),limit=number(a,"limit",100,1,1000);
            try(FileDataTypeManager archive=FileDataTypeManager.openFileArchive(path.toFile(),false)){
                int count=0;List<Map<String,Object>> rows=new ArrayList<>();for(var it=archive.getAllDataTypes();it.hasNext();){m.checkCancelled();DataType type=it.next();if(count++>=offset&&rows.size()<limit)rows.add(typeRow(type));}
                return ok(Map.of("path",path.toString(),"sha256",fileHash(path,m),"name",archive.getName(),"count",count,"offset",offset,"truncated",(long)offset+rows.size()<count,"types",rows));
            }
        }
    }
    static final class ParseC extends NativeTool {
        public boolean isOpenWorld(){return true;}
        public String getName(){return "parse_c_declarations";}
        public String getDescription(){return "Parse C declaration text or explicit header_paths into a staged GDT for review. max_bytes limits explicit inputs only, not transitive includes or macro expansion. Uses a selected language/compiler and never modifies the program.";}
        public boolean isReadOnly(){return false;}
        public McpSchema.JsonSchema getInputSchema(){return schema(Map.of("text",prop("string"),"header_paths",array("string",32),"include_paths",array("string",16),"language",prop("string"),"compiler",prop("string"),"max_bytes",prop("integer")));}
        McpSchema.CallToolResult run(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,TaskMonitor m)throws Exception{
            boolean textMode=a.containsKey("text");if(textMode==a.containsKey("header_paths"))throw new IllegalArgumentException("Specify exactly one of text or header_paths");
            String language=a.containsKey("language")?required(a,"language"):p==null?null:p.getLanguageID().toString();
            String compiler=a.containsKey("compiler")?required(a,"compiler"):p==null?null:p.getCompilerSpec().getCompilerSpecID().toString();
            if(language==null||compiler==null)throw new IllegalArgumentException("Select a program or specify both language and compiler");
            int cap=number(a,"max_bytes",200000,1,2000000);List<String> headers=new ArrayList<>();List<String> include=new ArrayList<>();
            for(String dir:strings(a,"include_paths",16,false)){Path path=Path.of(dir).toRealPath();if(!Files.isDirectory(path))throw new IllegalArgumentException("Include path must be a directory");include.add(path.toString());}
            String declarations=textMode?required(a,"text"):null;
            if(textMode){if(declarations.getBytes(StandardCharsets.UTF_8).length>cap)throw new IllegalArgumentException("Declaration text exceeds max_bytes");if(declarations.matches("(?s).*#\\s*(include|import).*"))throw new IllegalArgumentException("Use header_paths for includes; text mode accepts declarations only");}
            else {long total=0;for(String header:strings(a,"header_paths",32,true)){Path path=Path.of(header).toRealPath();if(!Files.isRegularFile(path))throw new IllegalArgumentException("Header must be a file");total+=Files.size(path);if(total>cap)throw new IllegalArgumentException("Explicit header inputs exceed max_bytes");headers.add(path.toString());}}
            Path root=Path.of(System.getProperty("java.io.tmpdir"),"ghidrassistmcp-staging");Files.createDirectories(root);Path work=Files.createTempDirectory(root,"c-");Path archivePath=work.resolve("types.gdt");Path input=work.resolve("declarations.h");boolean keep=false;
            try{
                if(textMode){Files.writeString(input,declarations);headers.add(input.toString());}
                try(FileDataTypeManager archive=FileDataTypeManager.createFileArchive(archivePath.toFile(),language,compiler)){
                    // Parse in isolation: the staging archive must retain every requested definition.
                    CParserUtils.CParseResults parsed;
                    synchronized(PARSER_LOCK){m.checkCancelled();parsed=CParserUtils.parseHeaderFiles(new DataTypeManager[0],headers.toArray(String[]::new),include.toArray(String[]::new),new String[0],archive,m);}m.checkCancelled();
                    if(!parsed.successful())return McpSchema.CallToolResult.builder().isError(true).structuredContent(Map.of("successful",false,"cpp_diagnostics",Objects.toString(parsed.cppParseMessages(),""),"c_diagnostics",Objects.toString(parsed.cParseMessages(),""))).addTextContent(Objects.toString(parsed.getFormattedParseMessage(null),"C parsing failed")).build();
                    archive.save();List<Map<String,Object>> rows=new ArrayList<>();int count=0;for(var it=archive.getAllDataTypes();it.hasNext();){m.checkCancelled();DataType type=it.next();count++;if(rows.size()<1000)rows.add(typeRow(type));}
                    keep=true;return ok(Map.of("successful",true,"staging_path",archivePath.toString(),"types",rows,"count",count,"truncated",count>rows.size(),"language",language,"compiler",compiler,"cpp_diagnostics",Objects.toString(parsed.cppParseMessages(),""),"c_diagnostics",Objects.toString(parsed.cParseMessages(),"")));
                }
            }finally{Files.deleteIfExists(input);if(!keep){try(var files=Files.list(work)){for(Path file:files.toList())if(Files.isRegularFile(file))Files.deleteIfExists(file);}Files.deleteIfExists(work);}}
        }
    }
    static Map<String,DataType> dependencies(Collection<DataType> roots,TaskMonitor m)throws Exception{
        Map<String,DataType> out=new TreeMap<>();Deque<DataType> todo=new ArrayDeque<>(roots);
        while(!todo.isEmpty()){m.checkCancelled();DataType type=todo.remove();if(out.putIfAbsent(type.getPathName(),type)!=null)continue;if(out.size()>10000)throw new IllegalArgumentException("Type dependency closure exceeds 10000 entries");
            if(type instanceof BitFieldDataType bitfield)todo.add(bitfield.getBaseDataType());
            else if(type instanceof Composite c){for(var component:c.getDefinedComponents())todo.add(component.getDataType());}
            else if(type instanceof Array array)todo.add(array.getDataType());else if(type instanceof Pointer pointer){if(pointer.getDataType()!=null)todo.add(pointer.getDataType());}
            else if(type instanceof TypeDef typedef)todo.add(typedef.getDataType());else if(type instanceof FunctionDefinition function){todo.add(function.getReturnType());for(var parameter:function.getArguments())todo.add(parameter.getDataType());}
        }return out;
    }
    static final class ImportTypes extends NativeTool {
        public boolean isOpenWorld(){return true;}
        private static DataTypeConflictHandler conflictHandler(String policy){return new DataTypeConflictHandler(){
            public ConflictResult resolveConflict(DataType added,DataType existing){return policy.equals("replace")?ConflictResult.REPLACE_EXISTING:ConflictResult.USE_EXISTING;}
            public boolean shouldUpdate(DataType source,DataType local){return policy.equals("replace");}
            public DataTypeConflictHandler getSubsequentHandler(){return this;}
        };}
        public String getName(){return "datatype_import_selected";}
        public String getDescription(){return "Preview then import exact GDT type paths with dependency conflicts. Writes require dry_run=false and the returned preview_token; preserve, replace or fail policy is explicit.";}
        public boolean isReadOnly(){return false;}
        public McpSchema.JsonSchema getInputSchema(){return schema(Map.of("path",prop("string"),"names",array("string",500),"conflict_policy",Map.of("type","string","enum",List.of("preserve","replace","fail")),"dry_run",Map.of("type","boolean","default",true),"preview_token",prop("string")),"path","names");}
        McpSchema.CallToolResult run(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,TaskMonitor m)throws Exception{
            if(p==null||p.isClosed())throw new IllegalArgumentException("Open target program required");Path path=Path.of(required(a,"path")).toRealPath();List<String> names=strings(a,"names",500,true);if(new HashSet<>(names).size()!=names.size())throw new IllegalArgumentException("Duplicate type paths");
            String policy=a.containsKey("conflict_policy")?required(a,"conflict_policy"):"preserve";if(!Set.of("preserve","replace","fail").contains(policy))throw new IllegalArgumentException("Unknown conflict_policy");
            boolean dry=!Boolean.FALSE.equals(a.get("dry_run"));long revision=p.getModificationNumber();String archiveHash=fileHash(path,m);
            try(FileDataTypeManager src=FileDataTypeManager.openFileArchive(path.toFile(),false)){
                List<DataType> selected=new ArrayList<>();for(String name:names){DataType type=src.getDataType(name);if(type==null||!name.equals(type.getPathName()))throw new IllegalArgumentException("Exact archive type path not found: "+name);selected.add(type);}
                var closure=dependencies(selected,m);List<Map<String,Object>> conflicts=new ArrayList<>();
                for(var entry:closure.entrySet()){
                    DataType incoming=entry.getValue();Set<DataType> existingTypes=new LinkedHashSet<>();
                    existingTypes.add(p.getDataTypeManager().getDataType(entry.getKey()));
                    if(incoming.getSourceArchive()!=null&&incoming.getUniversalID()!=null)
                        existingTypes.add(p.getDataTypeManager().getDataType(incoming.getSourceArchive(),incoming.getUniversalID()));
                    for(DataType existing:existingTypes)if(existing!=null&&!existing.isEquivalent(incoming))
                        conflicts.add(Map.of("path",entry.getKey(),"existing_path",existing.getPathName(),"existing_length",existing.getLength(),"incoming_length",incoming.getLength()));
                }
                String token=hash(JSON.writeValueAsBytes(Map.of("archive",path.toString(),"sha256",archiveHash,"program",ProgramIdentity.id(p),"revision",revision,"paths",new TreeSet<>(names),"policy",policy)));
                if(p.getModificationNumber()!=revision)throw new IllegalStateException("Program changed during preview");
                if(dry)return ok(Map.of("committed",false,"dry_run",true,"preview_token",token,"types",names,"count",names.size(),"dependency_count",closure.size(),"conflicts",conflicts,"can_apply",!policy.equals("fail")||conflicts.isEmpty()));
                if(!token.equals(required(a,"preview_token")))throw new IllegalStateException("Stale preview_token; preview the archive and target again");
                if(policy.equals("fail")&&!conflicts.isEmpty())throw new IllegalArgumentException("Dependency conflicts prevent import: "+conflicts);
                if(!p.isChangeable()||(p.getDomainFile().getProjectLocator()!=null&&p.getDomainFile().isReadOnly())||p.getCurrentTransactionInfo()!=null)throw new IllegalStateException("Target must be writable and have no active transaction");
                if(!archiveHash.equals(fileHash(path,m)))throw new IllegalStateException("Archive changed during preview");
                int tx=p.startTransaction("MCP selected type import");boolean commit=false;
                try{if(p.getModificationNumber()!=revision)throw new IllegalStateException("Program changed before import");List<Map<String,Object>> results=new ArrayList<>();for(DataType type:selected){m.checkCancelled();DataType resolved=p.getDataTypeManager().addDataType(type,conflictHandler(policy));results.add(typeRow(resolved));}m.checkCancelled();commit=true;return ok(Map.of("committed",true,"count",results.size(),"types",results,"saved",false));}finally{p.endTransaction(tx,commit);}
            }
        }
    }
    static final class Diff extends NativeTool {
        public String getName(){return "program_diff";}
        public String getDescription(){return "Read-only aligned native ProgramDiff between two exact open program selectors, with category/range filters and bounded output. Does not align relocated programs or merge.";}
        public McpSchema.JsonSchema getInputSchema(){return schema(Map.of("program_a",prop("string"),"program_b",prop("string"),"categories",array("string",10),"start",prop("string"),"end",prop("string"),"max_records",prop("integer")),"program_a","program_b");}
        McpSchema.CallToolResult run(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,TaskMonitor m)throws Exception{
            if(b==null)throw new IllegalArgumentException("Backend required for exact program selection");Program x=ProgramIdentity.resolve(required(a,"program_a"),b.getAllOpenPrograms()),y=ProgramIdentity.resolve(required(a,"program_b"),b.getAllOpenPrograms());
            int flags=ProgramDiffFilter.ALL_DIFFS;if(a.containsKey("categories")){flags=0;for(String category:strings(a,"categories",10,true))flags|=switch(category){case "bytes","memory"->ProgramDiffFilter.BYTE_DIFFS;case "comments"->ProgramDiffFilter.COMMENT_DIFFS;case "symbols"->ProgramDiffFilter.SYMBOL_DIFFS;case "functions"->ProgramDiffFilter.FUNCTION_DIFFS;case "code"->ProgramDiffFilter.CODE_UNIT_DIFFS;case "references"->ProgramDiffFilter.REFERENCE_DIFFS;default->throw new IllegalArgumentException("Unknown diff category: "+category);};}
            AddressSet restricted=null;if(a.containsKey("start")||a.containsKey("end")){Address start=x.getAddressFactory().getAddress(required(a,"start")),end=x.getAddressFactory().getAddress(required(a,"end"));if(start==null||end==null||!start.getAddressSpace().equals(end.getAddressSpace())||start.compareTo(end)>0)throw new IllegalArgumentException("Invalid inclusive range in program_a");restricted=new AddressSet(start,end);}
            int cap=number(a,"max_records",1000,1,10000);long xr=x.getModificationNumber(),yr=y.getModificationNumber();ProgramDiff diff=new ProgramDiff(x,y,restricted);AddressSetView differences=diff.getDifferences(new ProgramDiffFilter(flags),m);
            if(restricted!=null)differences=new AddressSet(differences).intersect(restricted);
            List<String> rows=new ArrayList<>();for(Address address:differences.getAddresses(true)){m.checkCancelled();if(rows.size()==cap)break;rows.add(address.toString());}
            return ok(Map.of("program_a",ProgramIdentity.id(x),"program_b",ProgramIdentity.id(y),"addresses",rows,"count",differences.getNumAddresses(),"truncated",differences.getNumAddresses()>rows.size(),"categories",flags,"warnings",Objects.toString(diff.getWarnings(),""),"changed_during_query",xr!=x.getModificationNumber()||yr!=y.getModificationNumber()));
        }
    }
    static final class FidCatalog extends NativeTool {
        public String getName(){return "fid_list_databases";}
        public String getDescription(){return "Catalog native Function ID databases and library/language metadata; opens local databases read-only and reports per-file errors.";}
        public McpSchema.JsonSchema getInputSchema(){return schema(Map.of("limit",prop("integer")));}
        McpSchema.CallToolResult run(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,TaskMonitor m)throws Exception{
            List<Map<String,Object>> rows=new ArrayList<>();var files=FidFileManager.getInstance().getFidFiles();int cap=number(a,"limit",100,1,500);
            for(FidFile file:files){m.checkCancelled();if(rows.size()==cap)break;Map<String,Object> row=new LinkedHashMap<>();row.put("path",file.getPath());row.put("name",file.getName());row.put("active",file.isActive());row.put("installed",file.isInstalled());
                try(FidDB db=file.getFidDB(false)){List<Map<String,Object>> libraries=new ArrayList<>();var all=db.getAllLibraries();for(var library:all){m.checkCancelled();if(libraries.size()==1000)break;libraries.add(Map.of("family",library.getLibraryFamilyName(),"version",library.getLibraryVersion(),"variant",library.getLibraryVariant(),"language",library.getGhidraLanguageID().toString()));}row.put("libraries",libraries);row.put("libraries_truncated",all.size()>libraries.size());row.put("status","available");}
                catch(ghidra.util.exception.CancelledException e){throw e;}catch(Exception e){row.put("status",e instanceof ghidra.util.exception.VersionException?"incompatible":"unreadable");row.put("error",Objects.toString(e.getMessage(),e.getClass().getSimpleName()));}rows.add(row);
            }return ok(Map.of("status",files.isEmpty()?"no_database":"catalogued","databases",rows,"truncated",files.size()>rows.size()));
        }
    }
    static final class FidLookup extends NativeTool {
        public String getName(){return "fid_identify_functions";}
        public String getDescription(){return "Query native Function ID for one function entry or a bounded page of functions. Returns candidate names and library provenance; never applies labels.";}
        public McpSchema.JsonSchema getInputSchema(){return schema(Map.of("address",prop("string"),"threshold",prop("number"),"limit",prop("integer"),"offset",prop("integer"),"candidate_offset",prop("integer"),"max_functions",prop("integer")));}
        McpSchema.CallToolResult run(Map<String,Object>a,Program p,GhidrAssistMCPBackend b,TaskMonitor m)throws Exception{
            if(p==null)throw new IllegalArgumentException("Program required");float threshold=FidService.SCORE_THRESHOLD;if(a.containsKey("threshold")){if(!(a.get("threshold") instanceof Number n)||!Float.isFinite(n.floatValue())||n.floatValue()<0)throw new IllegalArgumentException("Invalid threshold");threshold=n.floatValue();}
            int cap=number(a,"limit",20,1,500),max=number(a,"max_functions",100,1,1000),offset=number(a,"offset",0,0,1000000);List<Function> functions=new ArrayList<>();boolean more=false;
            if(a.containsKey("address")){Address address=p.getAddressFactory().getAddress(required(a,"address"));if(address==null)throw new IllegalArgumentException("Invalid address");Function f=p.getFunctionManager().getFunctionAt(address);if(f==null)return ok(Map.of("status","no_function","matches",List.of()));functions.add(f);}
            else{int seen=0;for(Function f:p.getFunctionManager().getFunctions(true)){m.checkCancelled();if(seen++<offset)continue;if(functions.size()==max){more=true;break;}functions.add(f);}}
            var manager=FidFileManager.getInstance();if(manager.getFidFiles().isEmpty())return ok(Map.of("status","no_database","matches",List.of()));if(!manager.canQuery(p.getLanguage()))return ok(Map.of("status","no_compatible_database","language",p.getLanguageID().toString(),"matches",List.of()));
            List<Map<String,Object>> matches=new ArrayList<>();int scanned=0,unhashable=0,nextOffset=offset,nextCandidate=0;
            int candidateOffset=number(a,"candidate_offset",0,0,1000000);boolean truncated=false;long revision=p.getModificationNumber();
            try(FidQueryService query=manager.openFidQueryService(p.getLanguage(),false)){
                var seeker=new FidService().getProgramSeeker(p,query,threshold);
                for(Function f:functions){m.checkCancelled();FidSearchResult result=seeker.searchFunction(f,m);scanned++;nextOffset=offset+scanned;if(result==null){unhashable++;continue;}if(result.matches==null)continue;
                    int candidate=0;
                    for(FidMatch match:result.matches){m.checkCancelled();if(scanned==1&&candidate<candidateOffset){candidate++;continue;}if(matches.size()==cap){truncated=true;nextOffset=offset+scanned-1;nextCandidate=candidate;break;}var record=match.getFunctionRecord();var library=match.getLibraryRecord();matches.add(Map.of("function",f.getEntryPoint().toString(),"target_name",f.getName(),"candidate_name",record.getName(),"score",match.getOverallScore(),"library",library.getLibraryFamilyName(),"version",library.getLibraryVersion(),"variant",library.getLibraryVariant(),"full_hash",Long.toUnsignedString(record.getFullHash(),16),"specific_hash",Long.toUnsignedString(record.getSpecificHash(),16)));candidate++;}if(truncated)break;
                }
            }
            return ok(Map.of("status",!matches.isEmpty()?"matches":scanned>0&&unhashable==scanned?"unhashable":"no_match","matches",matches,"functions_scanned",scanned,"unhashable_functions",unhashable,"threshold",threshold,"truncated",truncated||more||scanned<functions.size(),"next_offset",nextOffset,"next_candidate_offset",nextCandidate,"changed_during_query",revision!=p.getModificationNumber()));
        }
    }
}
