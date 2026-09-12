package ghidrassistmcp.nativeapi;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import ghidrassistmcp.McpTool;

/** Contract coverage that does not require a headed Ghidra tool. Runtime ProgramDB tests exercise the same tools. */
public class NativeAnalysisToolsContractTest {
    @Test public void exposesCompleteNativeFamily() {
        Set<String> names=new HashSet<>(); for(McpTool t:NativeAnalysisTools.tools()) names.add(t.getName());
        assertEquals(Set.of("datatype_archive_catalog","parse_c_declarations","datatype_import_selected","program_diff","fid_list_databases","fid_identify_functions"),names);
    }
    @Test public void allToolsHaveSchemasAndDescriptions() {
        for(McpTool t:NativeAnalysisTools.tools()){assertNotNull(t.getInputSchema());assertFalse(t.getDescription().isBlank());}
    }
}
