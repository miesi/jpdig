# jpdig - Java Parallel Dig

A parallel DNS trace tool similar to `dig +trace` with enhanced validation, written in Java.

## Features

- **Parallel DNS queries**: All nameserver IPs at each delegation level are queried in parallel using Java virtual threads
- **Full NS delegation trace**: Traces the NS delegation chain from root servers to the target domain
- **IPv4 and IPv6**: Resolves and queries all A and AAAA addresses for each nameserver
- **Out-of-bailiwick NS resolution**: When a referral has NS records without glue (nameservers in a different zone), their addresses are resolved iteratively from the root
- **Automatic connectivity detection**: Detects whether IPv4, IPv6 or dual-stack is available; silently skips unavailable protocols
- **NS consistency checking**: Compares NS record sets between delegating (parent) and authoritative (child) zones
- **NS variant detection**: Detects when different servers at the same level return different NS sets
- **TTL validation**: Warns for TTLs below 3600s, errors for TTLs below 600s
- **TTL comparison**: Compares NS record TTLs between delegation and authoritative responses
- **Glue record validation**: Verifies that glue addresses match authoritative A/AAAA records
- **NSID support**: Optional NSID (RFC 5001) queries to identify anycast nodes
- **IP info / ASN lookup**: Optional Cymru-style AS/prefix/country/RIR/allocation-date display per queried IP (mtr-compatible `-z` and `-y` flags)
- **Latency measurement**: Measures and displays query latency for every DNS query
- **Per-level statistics**: Query counts (UDP/TCP/failed), min/max latency per level
- **TCP support**: Force TCP mode, or automatic TCP fallback on truncated UDP responses (with warning)
- **Colored output**: ANSI colored terminal output with severity indicators
- **JSON output**: Machine-readable JSON output for scripting and automation
- **No recursion**: All trace queries are sent with RD=0 (Recursion Desired unset)

## Requirements

- Java 25 or later
- Maven 3.9+ (for building)

## Building

```bash
mvn clean package
```

This produces a fat JAR at `target/jpdig-1.0-SNAPSHOT.jar`.

## Installation

After building, you can use the shell wrapper for convenient invocation:

```bash
# Option 1: Use the wrapper from the build directory
./bin/jpdig example.com

# Option 2: Copy to a directory in your PATH
cp bin/jpdig /usr/local/bin/
cp target/jpdig-1.0-SNAPSHOT.jar /usr/local/bin/jpdig.jar

# Option 3: Create a symlink
ln -s "$(pwd)/bin/jpdig" /usr/local/bin/jpdig
```

## Usage

```
jpdig [options] <domain>

Options:
  -h, --help        Show help message and exit
  -V, --version     Print version information and exit
  --tcp             Force TCP for all queries (default: UDP with TCP fallback)
  --nsid            Request NSID (Name Server Identifier) from servers
  --json            Output results in JSON format
  --no-color        Disable colored terminal output
  -t, --timeout=N   Query timeout in milliseconds (default: 100)
  -r, --retries=N   Number of retries per query (default: 0)
  -z, --aslookup    Display AS number for each queried IP (= --ipinfo 0)
  -y, --ipinfo=SPEC Display IP info per queried IP. SPEC is a combinable list
                    of digits 0..4, given as a string ("013") or comma list
                    ("0,1,3"):
                      0 = AS number
                      1 = IP prefix
                      2 = country code
                      3 = RIR
                      4 = allocation date
  --ipinfo_provider4=DOMAIN
                    Provider for IPv4 AS lookups (default: origin.asn.cymru.com)
  --ipinfo_provider6=DOMAIN
                    Provider for IPv6 AS lookups (default: origin6.asn.cymru.com)
```

## Examples

### Basic trace
```bash
jpdig example.com
```

### Trace with NSID to see anycast nodes
```bash
jpdig --nsid example.com
```

### Force TCP queries
```bash
jpdig --tcp example.com
```

### JSON output for scripting
```bash
jpdig --json example.com | jq '.levels[].validations'
```

### Custom timeout and retries
```bash
jpdig --timeout 500 --retries 2 example.com
```

### Show ASN per queried IP
```bash
jpdig -z example.com
```

### Show AS, prefix and RIR
```bash
jpdig -y 013 example.com
# or equivalently
jpdig -y 0,1,3 example.com
```

The selected fields are appended to the existing `[NSID:...]` bracket per
query line, in canonical order, space-separated:

```
2a02:568:fe02::de (z.nic.de.) UDP 6.0ms [NSID:k.r.defra-4 AS:31529 PREFIX:2a02:568:fe02::/48 RIR:ripencc]
```

Lookups use Cymru's `origin.asn.cymru.com` / `origin6.asn.cymru.com` TXT
service via the local stub resolver. Override with `--ipinfo_provider4` and
`--ipinfo_provider6`. Results are cached per IP for the duration of a
single trace run.

## Output Explanation

### Severity Levels

- **[OK]** (green): Validation passed
- **[WARN]** (yellow): Potential issue detected (e.g., TTL < 3600s, NS set mismatch)
- **[ERR]** (red): Significant issue (e.g., TTL < 600s)

### Per-Level Information

For each delegation level, jpdig shows:

1. **Delegation NS**: NS records received from the parent zone's referral
2. **Delegation Queries**: Individual query results to parent servers (IP, protocol, latency, NSID)
3. **Glue Records**: Glue A/AAAA records from the parent's ADDITIONAL section
4. **NS Address Resolutions**: A/AAAA lookups for NS names with latency
5. **Authoritative NS**: NS records from querying the zone's own servers
6. **Authoritative Queries**: Individual query results to the zone's servers
7. **Glue Validation**: Comparison of glue IPs vs authoritative IPs
8. **Validations**: All checks (NS consistency, TTL comparison, TTL thresholds)
9. **Statistics**: Query counts and latency ranges

### TCP Fallback

When a UDP response is truncated (TC flag set), jpdig automatically retries over TCP and marks the query with `TCP(fallback)` along with a warning.

## How It Works

1. **Connectivity detection**: Tests IPv4 and IPv6 connectivity by sending a minimal DNS query to a root server
2. **Domain decomposition**: Splits the target domain into zone levels (e.g., `example.com.` → `[com., example.com.]`)
3. **Root query**: Queries all reachable root server IPs for the target domain to get the first referral
4. **Level iteration**: For each zone level:
   - Extracts delegation NS and glue from the parent's referral
   - Resolves all NS names to A and AAAA records (using glue where available)
   - Queries all resolved IPs for the zone's own NS records (authoritative)
   - Compares delegation vs. authoritative NS sets
   - Validates TTLs and glue records
   - Collects statistics
5. **Output**: Formats results as colored text or JSON

## License

MIT
