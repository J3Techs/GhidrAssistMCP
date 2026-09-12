package ghidrassistmcp.vt;

import java.util.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;

/** Validated JSON to native VT ToolOptions conversion. */
public final class VTOptionsSupport {
    private VTOptionsSupport() {}
    private static final Object[][] DEFAULTS = {
        {VTOptionDefines.FUNCTION_NAME, VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_NAME},
        {VTOptionDefines.FUNCTION_SIGNATURE, VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE},
        {VTOptionDefines.FUNCTION_RETURN_TYPE, VTOptionDefines.DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE},
        {VTOptionDefines.LABELS, VTOptionDefines.DEFAULT_OPTION_FOR_LABELS},
        {VTOptionDefines.PLATE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_PLATE_COMMENTS},
        {VTOptionDefines.PRE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_PRE_COMMENTS},
        {VTOptionDefines.END_OF_LINE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_EOL_COMMENTS},
        {VTOptionDefines.REPEATABLE_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS},
        {VTOptionDefines.POST_COMMENT, VTOptionDefines.DEFAULT_OPTION_FOR_POST_COMMENTS},
        {VTOptionDefines.DATA_MATCH_DATA_TYPE, VTOptionDefines.DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE},
        {VTOptionDefines.CALLING_CONVENTION, VTOptionDefines.DEFAULT_OPTION_FOR_CALLING_CONVENTION},
        {VTOptionDefines.INLINE, VTOptionDefines.DEFAULT_OPTION_FOR_INLINE},
        {VTOptionDefines.NO_RETURN, VTOptionDefines.DEFAULT_OPTION_FOR_NO_RETURN},
        {VTOptionDefines.PARAMETER_DATA_TYPES, VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES},
        {VTOptionDefines.PARAMETER_NAMES, VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_NAMES},
        {VTOptionDefines.HIGHEST_NAME_PRIORITY, VTOptionDefines.DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY},
        {VTOptionDefines.PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY, VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY},
        {VTOptionDefines.PARAMETER_COMMENTS, VTOptionDefines.DEFAULT_OPTION_FOR_PARAMETER_COMMENTS},
        {VTOptionDefines.VAR_ARGS, VTOptionDefines.DEFAULT_OPTION_FOR_VAR_ARGS},
        {VTOptionDefines.CALL_FIXUP, VTOptionDefines.DEFAULT_OPTION_FOR_CALL_FIXUP},
        {VTOptionDefines.IGNORE_INCOMPLETE_MARKUP_ITEMS, VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS},
        {VTOptionDefines.IGNORE_EXCLUDED_MARKUP_ITEMS, VTOptionDefines.DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS}
    };
    public static ToolOptions applyOptions(Map<String,Object> supplied) {
        ToolOptions o=new ToolOptions(VTOptionDefines.APPLY_MARKUP_OPTIONS_NAME);
        for(Object[] d:DEFAULTS)o.registerOption((String)d[0],d[1],null,"Native Version Tracking markup option");
        configure(o,supplied==null?Map.of():supplied); return o;
    }
    public static void configure(ToolOptions options, Map<String,Object> supplied) {
        if(supplied==null)return;
        Set<String> names=new HashSet<>(options.getOptionNames());
        for(var e:supplied.entrySet()) {
            if(!names.contains(e.getKey()))throw new IllegalArgumentException("Unknown VT option: "+e.getKey());
            Object def=options.getObject(e.getKey(),options.getDefaultValue(e.getKey())), v=e.getValue();
            if(def instanceof Enum<?> en){ if(!(v instanceof String s))throw new IllegalArgumentException(e.getKey()+" requires enum name"); try { setEnum(options,e.getKey(),en.getDeclaringClass(),s); } catch(Exception ex){throw new IllegalArgumentException("Invalid enum value for "+e.getKey()+": "+s);} }
            else if(def instanceof Boolean){if(!(v instanceof Boolean))throw new IllegalArgumentException(e.getKey()+" requires boolean");options.setBoolean(e.getKey(),(Boolean)v);}
            else if(def instanceof Integer){if(!(v instanceof Number)||v instanceof Float||v instanceof Double||((Number)v).doubleValue()!=((Number)v).intValue())throw new IllegalArgumentException(e.getKey()+" requires integer");options.setInt(e.getKey(),((Number)v).intValue());}
            else if(def instanceof Long){if(!(v instanceof Number)||v instanceof Float||v instanceof Double)throw new IllegalArgumentException(e.getKey()+" requires number");options.setLong(e.getKey(),((Number)v).longValue());}
            else if(def instanceof Double||def instanceof Float){if(!(v instanceof Number)||!Double.isFinite(((Number)v).doubleValue()))throw new IllegalArgumentException(e.getKey()+" requires finite number");options.setDouble(e.getKey(),((Number)v).doubleValue());}
            else if(def instanceof String){if(!(v instanceof String))throw new IllegalArgumentException(e.getKey()+" requires string");options.setString(e.getKey(),(String)v);}
            else throw new IllegalArgumentException("Unsupported VT option type: "+e.getKey());
        }
    }
    @SuppressWarnings({"rawtypes","unchecked"}) private static void setEnum(ToolOptions o,String n,Class<?> type,String value){ o.setEnum(n,Enum.valueOf((Class)type,value)); }
    public static List<Map<String,Object>> describe(ToolOptions options) {
        List<Map<String,Object>> out=new ArrayList<>(); for(String n:options.getOptionNames()){Object d=options.getObject(n,options.getDefaultValue(n));Map<String,Object> r=new LinkedHashMap<>();r.put("name",n);r.put("type",d==null?"null":d.getClass().getSimpleName());r.put("default",d instanceof Enum<?>?((Enum<?>)d).name():d);r.put("description",options.getDescription(n));if(d instanceof Enum<?> e)r.put("choices",Arrays.stream(e.getDeclaringClass().getEnumConstants()).map(x->((Enum<?>)x).name()).toList());out.add(r);}return out;
    }
}
