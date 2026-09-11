package ghidrassistmcp.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import java.math.BigInteger;
import java.util.*;
import java.util.regex.Pattern;

/** Small, side-effect-free helpers shared by bounded batch query tools. */
final class BatchQuerySupport {
  static final int MAX_ROWS = 1000, MAX_BYTES = 1 << 20, MAX_FIELDS = 64;

  private BatchQuerySupport() {}

  static int integer(Map<String, Object> a, String k, int d, int max) {
    if (!a.containsKey(k)) return d;
    Object v = a.get(k);
    if (!(v instanceof Number n)) throw new IllegalArgumentException(k + " must be an integer");
    double raw = n.doubleValue();
    if (!Double.isFinite(raw) || raw != Math.rint(raw))
      throw new IllegalArgumentException(k + " must be an integer");
    long value;
    try { value = new java.math.BigDecimal(n.toString()).longValueExact(); }
    catch (ArithmeticException e) { throw new IllegalArgumentException(k + " exceeds integer bounds"); }
    if (value < 0 || value > max) throw new IllegalArgumentException(k + " must be 0.." + max);
    return (int) value;
  }

  static String text(Object o, String k) {
    if (!(o instanceof String s) || s.isBlank())
      throw new IllegalArgumentException(k + " is required");
    return s.trim();
  }

  static List<?> list(Object o, String k, int max) {
    if (!(o instanceof List<?> l) || l.isEmpty())
      throw new IllegalArgumentException(k + " must be a non-empty array");
    if (l.size() > max) throw new IllegalArgumentException(k + " exceeds " + max);
    return l;
  }

  static int checkedTotal(int total, int add) {
    if (add < 0 || total > MAX_BYTES - add)
      throw new IllegalArgumentException("total byte budget exceeded");
    return total + add;
  }

  static Address address(Program p, String s) {
    Address a = p.getAddressFactory().getAddress(s);
    if (a == null) throw new IllegalArgumentException("invalid address: " + s);
    return a;
  }

  static Map<String, Object> addr(Address a) {
    return Map.of(
        "address",
        a.toString(),
        "space",
        a.getAddressSpace().getName(),
        "offset",
        Long.toUnsignedString(a.getOffset()));
  }

  static Map<String, Object> symbol(Symbol s) {
    return Map.of(
        "name",
        s.getName(true),
        "address",
        s.getAddress().toString(),
        "space",
        s.getAddress().getAddressSpace().getName(),
        "type",
        String.valueOf(s.getSymbolType()),
        "source",
        String.valueOf(s.getSource()));
  }

  static Map<String, Object> function(Function f) {
    return Map.of(
        "name",
        f.getName(true),
        "entry",
        f.getEntryPoint().toString(),
        "space",
        f.getEntryPoint().getAddressSpace().getName(),
        "size",
        f.getBody().getNumAddresses());
  }

  static List<Map<String, Object>> symbolsAt(Program p, Address a) {
    List<Map<String, Object>> r = new ArrayList<>();
    for (Symbol s : p.getSymbolTable().getSymbols(a)) {
      if (r.size() >= 32) break;
      r.add(symbol(s));
    }
    return r;
  }

  static Map<String, Object> bytes(Program p, Address a, int n) {
    Map<String, Object> r = new LinkedHashMap<>();
    r.put("requested", n);
    r.put("address", a.toString());
    r.put("space", a.getAddressSpace().getName());
    byte[] b = new byte[n];
    int got = 0;
    List<String> warnings = new ArrayList<>();
    Memory m = p.getMemory();
    for (int i = 0; i < n; i++)
      try {
        b[i] = m.getByte(a.add(i));
        got++;
      } catch (Exception e) {
        warnings.add("offset " + i + ": " + e.getMessage());
        break;
      }
    r.put("read", got);
    r.put("hex", java.util.HexFormat.of().formatHex(Arrays.copyOf(b, got)));
    r.put("truncated", got < n);
    if (!warnings.isEmpty()) r.put("warnings", warnings);
    return r;
  }

  static boolean matches(String name, String q, String mode) {
    String n = name.toLowerCase(Locale.ROOT), x = q.toLowerCase(Locale.ROOT);
    return switch (mode) {
      case "exact" -> n.equals(x);
      case "glob" ->
          Pattern.compile(globRegex(x), Pattern.CASE_INSENSITIVE).matcher(name).matches();
      default -> n.contains(x);
    };
  }

  private static String globRegex(String s) {
    StringBuilder b = new StringBuilder("^");
    for (char c : s.toCharArray()) {
      if (c == '*') b.append(".*");
      else if (c == '?') b.append('.');
      else {
        if ("\\.^$|()[]{}+".indexOf(c) >= 0) b.append('\\');
        b.append(c);
      }
    }
    return b.append('$').toString();
  }

  static Object decodeInteger(String h, String endian, String type) {
    if (!List.of("big", "little").contains(endian)) throw new IllegalArgumentException("invalid endian");
    int w =
        switch (type) {
          case "u8", "i8" -> 1;
          case "u16", "i16" -> 2;
          case "u32", "i32" -> 4;
          case "u64", "i64" -> 8;
          default -> 0;
        };
    if (w == 0 || h.length() != w * 2) throw new IllegalArgumentException("short read");
    byte[] b = HexFormat.of().parseHex(h);
    BigInteger v = BigInteger.ZERO;
    for (int i = 0; i < w; i++) {
      int j = endian.equals("little") ? i : w - 1 - i;
      v = v.or(BigInteger.valueOf(b[j] & 255L).shiftLeft(8 * i));
    }
    if (endian.equals("big")) {
      v = BigInteger.ZERO;
      for (byte value : b) v = v.shiftLeft(8).or(BigInteger.valueOf(value & 255L));
    }
    if (type.charAt(0) == 'i' && v.testBit(w * 8 - 1))
      v = v.subtract(BigInteger.ONE.shiftLeft(w * 8));
    return w == 8 ? v.toString() : v.longValue();
  }
}
