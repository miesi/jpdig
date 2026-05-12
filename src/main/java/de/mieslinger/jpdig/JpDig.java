package de.mieslinger.jpdig;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.concurrent.Callable;

/**
 * jpdig - Java Parallel Dig
 *
 * A parallel DNS trace tool similar to dig +trace with enhanced validation.
 * Traces NS delegation chain with parallel queries, latency measurement,
 * TTL validation, glue verification, and NSID support.
 */
@Command(name = "jpdig",
        mixinStandardHelpOptions = true,
        version = "jpdig 1.0",
        description = "Java Parallel Dig - DNS trace with enhanced validation.%n"
                + "Traces NS delegation chain from root to the target domain,%n"
                + "querying all nameserver IPs in parallel at each level.")
public class JpDig implements Callable<Integer> {

    @Parameters(index = "0", description = "Domain name to trace")
    private String domain;

    @Option(names = {"--tcp"},
            description = "Force TCP for all queries (default: UDP with TCP fallback)")
    private boolean forceTcp;

    @Option(names = {"--nsid"},
            description = "Request NSID (Name Server Identifier) from servers")
    private boolean requestNsid;

    @Option(names = {"--json"},
            description = "Output results in JSON format")
    private boolean jsonOutput;

    @Option(names = {"--no-color"},
            description = "Disable colored terminal output")
    private boolean noColor;

    @Option(names = {"--timeout", "-t"},
            description = "Query timeout in milliseconds (default: ${DEFAULT-VALUE})",
            defaultValue = "100")
    private int timeoutMs;

    @Option(names = {"--retries", "-r"},
            description = "Number of retries per query (default: ${DEFAULT-VALUE})",
            defaultValue = "0")
    private int retries;

    @Option(names = {"--aslookup", "-z"},
            description = "Display AS number for each queried server IP "
                    + "(equivalent to --ipinfo 0)")
    private boolean asLookup;

    @Option(names = {"--ipinfo", "-y"},
            description = "Display info per queried IP. Digits 0..4 (combinable, "
                    + "e.g. \"013\" or \"0,1,3\"): "
                    + "0=AS, 1=prefix, 2=country, 3=RIR, 4=allocation date.")
    private String ipInfoSpec;

    @Option(names = {"--ipinfo_provider4"},
            description = "Provider domain for IPv4 AS lookups "
                    + "(default: ${DEFAULT-VALUE})",
            defaultValue = "origin.asn.cymru.com")
    private String ipInfoProvider4;

    @Option(names = {"--ipinfo_provider6"},
            description = "Provider domain for IPv6 AS lookups "
                    + "(default: ${DEFAULT-VALUE})",
            defaultValue = "origin6.asn.cymru.com")
    private String ipInfoProvider6;

    @Override
    public Integer call() {
        try {
            // Normalize domain to FQDN
            if (!domain.endsWith(".")) {
                domain = domain + ".";
            }

            // Parse ipinfo field selection
            IpInfoFields ipInfoFields;
            try {
                ipInfoFields = IpInfoFields.parse(ipInfoSpec, asLookup);
            } catch (IllegalArgumentException e) {
                System.err.println("ERROR: " + e.getMessage());
                return 2;
            }
            IpInfoLookup ipInfoLookup = ipInfoFields.isEmpty()
                    ? null
                    : new IpInfoLookup(ipInfoProvider4, ipInfoProvider6, timeoutMs);

            // Detect IPv4/IPv6 connectivity
            if (!jsonOutput) {
                System.err.println("Detecting connectivity...");
            }
            TraceModel.ConnectivityInfo connectivity = ConnectivityDetector.detect(timeoutMs);

            if (!connectivity.ipv4Available() && !connectivity.ipv6Available()) {
                System.err.println("ERROR: No IPv4 or IPv6 connectivity available.");
                return 1;
            }

            // Create DNS client
            DnsClient dnsClient = new DnsClient(timeoutMs, retries, forceTcp, requestNsid);

            // Run trace
            if (!jsonOutput) {
                System.err.println("Starting trace for " + domain);
                System.err.println();
            }

            java.util.function.Consumer<String> progressListener = jsonOutput
                    ? msg -> {}
                    : msg -> System.err.println("  " + msg);

            TraceEngine engine = new TraceEngine(dnsClient, connectivity,
                    progressListener, timeoutMs, ipInfoLookup);
            TraceModel.TraceResult result = engine.trace(domain);

            // Output results
            if (jsonOutput) {
                new JsonOutput(ipInfoFields).print(result);
            } else {
                new ColoredOutput(!noColor, ipInfoFields).print(result);
            }

            return 0;
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            if (System.getProperty("jpdig.debug") != null) {
                e.printStackTrace();
            }
            return 1;
        }
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new JpDig()).execute(args);
        System.exit(exitCode);
    }
}
