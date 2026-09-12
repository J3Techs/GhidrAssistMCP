package ghidrassistmcp.vt;
/** Named factories used by the backend registration layer. */
public final class VTTools {
 private VTTools(){}
 public static VTTool sessions(){return new VTTool("vt_sessions");}
 public static VTTool session(){return new VTTool("vt_session");}
 public static VTTool correlators(){return new VTTool("vt_correlators");}
 public static VTTool correlate(){return new VTTool("vt_correlate");}
 public static VTTool matches(){return new VTTool("vt_matches");}
 public static VTTool reviewMatches(){return new VTTool("vt_review_matches");}
 public static VTTool addMatches(){return new VTTool("vt_add_matches");}
 public static VTTool markup(){return new VTTool("vt_markup");}
 public static VTTool applyMarkup(){return new VTTool("vt_apply_markup");}
 public static VTTool unapplyMarkup(){return new VTTool("vt_unapply_markup");}
}
