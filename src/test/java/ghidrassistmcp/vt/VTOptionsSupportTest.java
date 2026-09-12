package ghidrassistmcp.vt;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import ghidra.feature.vt.gui.util.VTOptionDefines;

class VTOptionsSupportTest {
    @Test void factoryOptionsWithoutRegisteredDefaultsCanBeConfigured(){
        var options=new ghidra.framework.options.ToolOptions("factory");options.setInt("Minimum Length",10);
        assertNull(options.getDefaultValue("Minimum Length"));VTOptionsSupport.configure(options,Map.of("Minimum Length",17));
        assertEquals(17,options.getInt("Minimum Length",0));assertEquals(17,VTOptionsSupport.describe(options).get(0).get("default"));
    }
    @Test void defaultsDescribeEnumsAndBooleans() {
        var o=VTOptionsSupport.applyOptions(Map.of(VTOptionDefines.FUNCTION_NAME,"REPLACE_ALWAYS",VTOptionDefines.IGNORE_INCOMPLETE_MARKUP_ITEMS,true));
        assertEquals("REPLACE_ALWAYS",o.getEnum(VTOptionDefines.FUNCTION_NAME,null).name()); assertTrue(o.getBoolean(VTOptionDefines.IGNORE_INCOMPLETE_MARKUP_ITEMS,false));
        var row=VTOptionsSupport.describe(o).stream().filter(x->x.get("name").equals(VTOptionDefines.FUNCTION_NAME)).findFirst().orElseThrow(); assertTrue(((List<?>)row.get("choices")).contains("REPLACE_ALWAYS"));
    }
    @Test void rejectsUnknownAndWrongTypes() {
        assertThrows(IllegalArgumentException.class,()->VTOptionsSupport.applyOptions(Map.of("missing",true)));
        assertThrows(IllegalArgumentException.class,()->VTOptionsSupport.applyOptions(Map.of(VTOptionDefines.IGNORE_INCOMPLETE_MARKUP_ITEMS,"true")));
        assertThrows(IllegalArgumentException.class,()->VTOptionsSupport.applyOptions(Map.of(VTOptionDefines.FUNCTION_NAME,"bogus")));
    }
}
