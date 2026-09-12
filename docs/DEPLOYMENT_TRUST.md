# Deployment and process ownership

GhidrAssistMCP is a local tool server with access to the Ghidra process, its open projects, and selected host files. Its clients share the backend's program state, task controls and cache. An MCP session ID separates transport sessions; it is not a per-user authorization boundary.

## Listener policy

The server now accepts only loopback bind addresses by default. It resolves the configured host once and binds to that resolved address. A non-loopback or wildcard listener requires the explicit JVM option:

```text
-Dghidrassistmcp.transport.allowRemote=true
```

This is an operator opt-in to remote exposure, not authentication. Such a deployment needs access control outside this server, for example an authenticated gateway and a restricted network path. Origin validation remains enabled and does not replace client authentication. Existing non-loopback configurations must add the option deliberately or switch to loopback.

## Scripts and native file tools

Existing public tools remain available under their established enabled states. `run_script` accepts explicit scripts and executes with the Ghidra process's privileges. Its lifetime is now tied to the actual runner; cancellation/timeout does not release mutation or program ownership while that runner is still alive. It is not a sandbox.

The GDT catalog, C parser and selected type importer intentionally accept host files; their open-world annotations now reflect that access. FID cataloging uses Ghidra's registered databases. The native parser's explicit-input byte limit does not bound transitive includes or macro expansion.

Use the existing enabled-tool configuration to remove capabilities a particular client should not access. The checked-in Codex profile is an optional client selection, not a server authorization policy. No new script-directory restriction is described as a sandbox, and no native tools are blanket-disabled by this repair.

## BSim authentication

Connection calls no longer silently replace JVM-global Ghidra authentication. With no MCP authentication configuration, calls reuse the process's existing authentication and do not install another handler.

An operator who wants this server to initialize nonprompting headless authentication must set the process configuration before opening a BSim connection:

```text
-Dghidrassistmcp.bsim.auth.user=<username>
-Dghidrassistmcp.bsim.auth.keystore=<absolute-readable-file>
```

Either property may be omitted. Configuration is applied once on first applicable connection. A profile/call that supplies `user` or `keystore` must agree with the configured values. Repeated equivalent settings are idempotent; conflicting settings or a later replacement of the authenticator fail explicitly. Different authentication identities that require different global configuration need separate JVMs.

The keystore path is canonicalized and must be a readable file. Existing classpath-resource keystore arguments need migration to an explicit file. If native initialization fails after partially modifying global state, retries are refused with restart guidance rather than continuing with uncertain credentials. Unit tests use a fake installation adapter and do not read credentials or connect to external databases.

## Compatibility boundaries

Safer mutation defaults are documented in the mutation repair evidence: ambiguous targets fail before mutation, incompatible type collisions require explicit replacement, and atomic batch failure reports rolled-back results. Temporary analysis options are restored after analysis stops. Query truncation is explicit; consumers should inspect bounds and continuation instead of assuming complete results.

These policies resolve the review's deployment ambiguity without treating every intended host-file capability as an implementation defect. They do not introduce per-client task ownership, a script sandbox, or remote authentication within the MCP server.
