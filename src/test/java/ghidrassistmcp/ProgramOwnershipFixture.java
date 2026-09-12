package ghidrassistmcp;

import java.lang.reflect.Proxy;
import java.util.*;
import ghidra.program.model.listing.Program;

/** Tracks real ownership calls without requiring a database or UI. */
public final class ProgramOwnershipFixture {
    public final Set<Object> consumers = Collections.synchronizedSet(Collections.newSetFromMap(new IdentityHashMap<>()));
    public final Program program = (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
        new Class<?>[] {Program.class}, (proxy, method, args) -> switch (method.getName()) {
            case "getName" -> "lifecycle-fixture";
            case "getDomainFile" -> null;
            case "isClosed" -> false;
            case "addConsumer" -> consumers.add(args[0]);
            case "isUsedBy" -> consumers.contains(args[0]);
            case "release" -> { if (!consumers.remove(args[0])) throw new AssertionError("Double consumer release"); yield null; }
            case "equals" -> proxy == args[0];
            case "hashCode" -> System.identityHashCode(proxy);
            case "toString" -> "LifecycleProgramFixture";
            default -> throw new UnsupportedOperationException(method.getName());
        });
}
