# CLAUDE.md - jpdig Development Guide

## Project Overview

**jpdig** (Java Parallel Dig) is a DNS trace tool similar to `dig +trace` with enhanced validation.
It traces NS delegation chains from root servers to a target domain, querying all nameserver IPs
in parallel at each level using Java virtual threads.

## Build & Run

```bash
# Build fat JAR
mvn clean package

# Run via wrapper script
./bin/jpdig example.com

# Run directly
java -jar target/jpdig-1.0-SNAPSHOT.jar example.com
```

**Requirements:** Java 25+, Maven 3.9+

## Architecture

```
JpDig.java              Entry point, CLI args (picocli)
TraceEngine.java         Core iterative resolution loop (main logic)
DnsClient.java           DNS query execution, timeout, TCP fallback, NSID
ConnectivityDetector.java IPv4/IPv6 availability detection
TraceModel.java          Immutable record types (data model)
Validator.java           TTL and NS set validation
RootHints.java           Hardcoded IANA root server addresses
ColoredOutput.java       ANSI colored terminal formatter
JsonOutput.java          JSON output formatter (Jackson)
```

### Resolution Flow (TraceEngine.trace())

1. Query root servers for target domain NS (parallel)
2. Analyze responses: authoritative → done, referral → continue, nothing → error
3. For referrals: resolve NS names to IPs (glue + iterative fallback)
4. Query zone's own servers for authoritative NS (parallel)
5. Validate NS consistency, TTLs, glue records
6. Repeat from step 2 with next delegation level
7. Loop guard: MAX_LEVELS = 20

### Key Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| --timeout, -t | 100ms | Per-query DNS timeout |
| --retries, -r | 0 | Retries per query |
| --tcp | false | Force TCP (default: UDP with TCP fallback) |
| --nsid | false | Request NSID (RFC 5001) |
| --json | false | JSON output |
| --no-color | false | Disable ANSI colors |

## Coding Conventions

- **Language:** All code, comments, variable/function names in English
- **Documentation:** README.md in English, prompt.txt (original spec) in German
- **Java version:** 25 (virtual threads, records, pattern matching)
- **DNS queries:** Always sent with RD=0 (no recursion desired)
- **Parallelization:** Virtual threads via `Executors.newVirtualThreadPerTaskExecutor()`
- **Data model:** Immutable Java records in TraceModel.java
- **Output:** ColoredOutput for terminal, JsonOutput for scripting
- **Connectivity:** Auto-detect IPv4/IPv6, silently skip unavailable protocols
- **Validation thresholds:** TTL warn < 3600s, TTL error < 600s

## Dependencies

- **picocli 4.7.6** - CLI argument parsing
- **dnsjava 3.6.2** - DNS protocol (SimpleResolver, Message, Record types)
- **Jackson 2.18.2** - JSON serialization
- **SLF4J 1.7.36** - Logging (NOP implementation, no output)

## Fixed Issues

### Referral loop and all-queries-failed detection (FIXED)

**Problem:** When tracing domains like `zaranew.noc.net.er`, the program would loop
through up to 20 levels (MAX_LEVELS) because nameservers kept returning the same referral
zone (`noc.net.er.`) without ever providing an authoritative answer. This caused hundreds
of queries and minutes of runtime, appearing as an infinite loop.

**Root causes identified:**
1. **Referral loop:** Nameservers for `noc.net.er.` (including `zaranew.noc.net.er.` itself)
   kept returning a referral to `noc.net.er.` instead of an authoritative answer.
2. **No all-queries-failed detection:** If all queries at a level failed (e.g., all servers
   exceeded the timeout), the program did not abort early.

**Fixes applied in TraceEngine.java:**
1. **Referral loop detection:** Track seen referral zones in a `Set<Name>`. If the same zone
   is referred again, abort with an ERROR message explaining the loop.
2. **All-queries-failed detection (delegation):** After `parallelQuery()` in the main loop,
   if `successCount == 0`, abort with a timeout hint (suggests `--timeout` increase).
3. **All-queries-failed detection (authoritative):** After querying zone servers for
   authoritative NS, if all queries fail, abort with a timeout hint.
