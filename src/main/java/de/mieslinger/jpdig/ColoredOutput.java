package de.mieslinger.jpdig;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import java.util.Comparator;

/**
 * Colored terminal output formatter for trace results.
 */
public class ColoredOutput {

    private final boolean useColor;
    private final IpInfoFields ipInfoFields;

    // ANSI color codes
    private static final String RESET = "\033[0m";
    private static final String BOLD = "\033[1m";
    private static final String RED = "\033[31m";
    private static final String GREEN = "\033[32m";
    private static final String YELLOW = "\033[33m";
    private static final String BLUE = "\033[34m";
    private static final String MAGENTA = "\033[35m";
    private static final String CYAN = "\033[36m";
    private static final String GRAY = "\033[90m";
    private static final String WHITE = "\033[97m";

    public ColoredOutput(boolean useColor) {
        this(useColor, IpInfoFields.empty());
    }

    public ColoredOutput(boolean useColor, IpInfoFields ipInfoFields) {
        this.useColor = useColor;
        this.ipInfoFields = ipInfoFields == null ? IpInfoFields.empty() : ipInfoFields;
    }

    public void print(TraceModel.TraceResult result) {
        printHeader(result);

        for (var level : result.levels()) {
            printLevel(level);
        }

        printSummary(result);
    }

    private void printHeader(TraceModel.TraceResult result) {
        println(bold("jpdig") + " - Java Parallel Dig - Tracing " + bold(result.domain()));
        println("");

        String v4 = result.ipv4Available() ? green("IPv4 OK") : red("IPv4 UNAVAILABLE");
        String v6 = result.ipv6Available() ? green("IPv6 OK") : red("IPv6 UNAVAILABLE");
        println("Connectivity: " + v4 + "  " + v6);
        println("");
    }

    private void printLevel(TraceModel.TraceLevel level) {
        String separator = "=".repeat(60);
        println(bold(cyan(separator)));
        String levelLabel = "  Level " + (level.levelNumber() + 1) + ": " + level.zoneName();
        if (level.isFinal()) levelLabel += " (authoritative)";
        println(bold(cyan(levelLabel)));
        println(bold(cyan(separator)));
        println("");

        // CNAME detection
        if (level.cnameTarget() != null) {
            println(bold("  CNAME:"));
            println("    " + level.zoneName() + " -> " + cyan(level.cnameTarget()));
            println("");
        }

        // Delegation NS
        if (!level.delegationNs().isEmpty()) {
            println(bold("  Delegation NS") + gray(" (from parent zone):"));
            for (String ns : level.delegationNs()) {
                println("    " + ns + "  " + formatTtlColored(level.delegationNsTtl()));
            }
            println("");
        }

        // Delegation server queries
        if (!level.delegationQueries().isEmpty()) {
            println(bold("  Delegation Queries:"));
            printServerQueries(sortByLatency(level.delegationQueries()));
            println("");
        }

        // NS variants (delegation)
        if (level.delegationNsVariants() != null && level.delegationNsVariants().size() > 1) {
            println(yellow("  Delegation NS Variants:"));
            for (var entry : level.delegationNsVariants().entrySet()) {
                println("    NS set: " + String.join(", ", entry.getKey()));
                println("    " + gray("from: " + String.join(", ", entry.getValue())));
            }
            println("");
        }

        // Glue records
        if (!level.glueRecords().isEmpty()) {
            println(bold("  Glue Records:"));
            for (var entry : level.glueRecords().entrySet()) {
                String addrs = entry.getValue().stream()
                        .map(InetAddress::getHostAddress)
                        .collect(Collectors.joining(", "));
                println("    " + entry.getKey() + " -> " + addrs);
            }
            println("");
        }

        // NS Address Resolutions
        List<TraceModel.NsAddressRecord> nonGlueResolutions = level.nsResolutions().stream()
                .filter(r -> !r.fromGlue())
                .sorted(Comparator.comparing(TraceModel.NsAddressRecord::latency))
                .toList();
        if (!nonGlueResolutions.isEmpty()) {
            println(bold("  NS Address Resolutions:"));
            for (var res : nonGlueResolutions) {
                println("    " + res.nsName() + " " + res.recordType()
                        + " -> " + res.address().getHostAddress()
                        + "  " + formatTtlColored(res.ttl())
                        + "  " + formatLatencyColored(res.latency())
                        + "  " + gray("via " + res.resolvedVia()));
            }
            println("");
        }

        // Authoritative NS
        if (!level.authoritativeNs().isEmpty()) {
            println(bold("  Authoritative NS") + gray(" (from zone itself):"));
            for (String ns : level.authoritativeNs()) {
                println("    " + ns + "  " + formatTtlColored(level.authoritativeNsTtl()));
            }
            println("");
        }

        // Authoritative server queries
        if (!level.authoritativeQueries().isEmpty()) {
            println(bold("  Authoritative Queries:"));
            printServerQueries(sortByLatency(level.authoritativeQueries()));
            println("");
        }

        // Authoritative NS variants
        if (level.authoritativeNsVariants() != null && level.authoritativeNsVariants().size() > 1) {
            println(yellow("  Authoritative NS Variants:"));
            for (var entry : level.authoritativeNsVariants().entrySet()) {
                println("    NS set: " + String.join(", ", entry.getKey()));
                println("    " + gray("from: " + String.join(", ", entry.getValue())));
            }
            println("");
        }

        // Glue Validations
        if (!level.glueValidations().isEmpty()) {
            println(bold("  Glue Validation:"));
            for (var gv : level.glueValidations()) {
                String status = gv.matches() ? green("MATCH") : yellow("MISMATCH");
                println("    " + gv.nsName() + ": " + status);
                if (!gv.matches()) {
                    println("      glue:           " + formatAddresses(gv.glueAddresses()));
                    println("      authoritative:  " + formatAddresses(gv.authoritativeAddresses()));
                }
            }
            println("");
        }

        // Validations
        if (!level.validations().isEmpty()) {
            println(bold("  Validations:"));
            for (var v : level.validations()) {
                String prefix = switch (v.severity()) {
                    case OK -> green("  [OK]   ");
                    case WARN -> yellow("  [WARN] ");
                    case ERROR -> red("  [ERR]  ");
                };
                println(prefix + v.message());
            }
            println("");
        }

        // Statistics
        printLevelStats("Delegation", level.delegationStats());
        printLevelStats("Authoritative", level.authoritativeStats());
        println("");
    }

    private void printServerQueries(List<TraceModel.ServerQueryDetail> queries) {
        for (var q : queries) {
            StringBuilder sb = new StringBuilder("    ");
            sb.append(q.serverAddress().getHostAddress());
            sb.append(" (").append(q.serverName() != null ? q.serverName() : "?").append(")");
            sb.append(" ").append(q.protocol());

            if (q.error() != null) {
                sb.append(" ").append(red("FAILED: " + q.error()));
            } else {
                sb.append(" ").append(formatLatencyColored(q.latency()));
                if (q.tcpFallback()) {
                    sb.append(" ").append(yellow("(TCP fallback - truncated)"));
                }
                String bracket = formatInfoBracket(q.nsid(), q.ipInfo());
                if (bracket != null) {
                    sb.append(" ").append(magenta(bracket));
                }
            }
            println(sb.toString());
        }
    }

    private void printLevelStats(String label, TraceModel.LevelStats stats) {
        if (stats == null || stats.totalQueries() == 0) return;

        println(gray("  " + label + " Stats: "
                + stats.totalQueries() + " queries ("
                + stats.udpQueries() + " UDP, "
                + stats.tcpQueries() + " TCP, "
                + stats.tcpFallbacks() + " fallbacks, "
                + stats.failedQueries() + " failed) "
                + "latency min=" + formatLatency(stats.minLatency())
                + " max=" + formatLatency(stats.maxLatency())));
    }

    private void printSummary(TraceModel.TraceResult result) {
        String separator = "=".repeat(60);
        println(bold(separator));
        println(bold("  Summary"));
        println(bold(separator));
        println("  Domain: " + result.domain());
        println("  Levels: " + result.levels().size());
        println("  Total queries: " + result.totalQueries()
                + " (" + result.nsQueries() + " NS, "
                + result.aQueries() + " A, "
                + result.aaaaQueries() + " AAAA)");
        println("  Total time: " + formatLatency(result.totalDuration()));
        println("");
    }

    /**
     * Build the "[NSID:... AS:... PREFIX:... COUNTRY:... RIR:... DATE:...]"
     * bracket. Pairs are space-separated, no spaces inside a key:value pair.
     * Returns null if there is nothing to show.
     */
    private String formatInfoBracket(String nsid, TraceModel.IpInfo info) {
        List<String> parts = new ArrayList<>();
        if (nsid != null) parts.add("NSID:" + nsid);
        for (IpInfoFields.Field f : IpInfoFields.Field.values()) {
            if (!ipInfoFields.contains(f)) continue;
            String value = IpInfoFields.value(f, info);
            if (value == null || value.isEmpty()) continue;
            String safe = value.replace(' ', '_');
            parts.add(IpInfoFields.label(f) + ":" + safe);
        }
        if (parts.isEmpty()) return null;
        return "[" + String.join(" ", parts) + "]";
    }

    // --- Formatting helpers ---

    private String formatLatency(Duration d) {
        if (d == null) return "N/A";
        double ms = d.toNanos() / 1_000_000.0;
        if (ms < 1) return String.format("%.1fms", ms);
        if (ms < 100) return String.format("%.1fms", ms);
        return String.format("%.0fms", ms);
    }

    private List<TraceModel.ServerQueryDetail> sortByLatency(List<TraceModel.ServerQueryDetail> queries) {
        return queries.stream()
                .sorted(Comparator.comparing(q -> q.latency() != null ? q.latency() : Duration.ofDays(1)))
                .toList();
    }

    private String formatTtlColored(long ttl) {
        String text = "[TTL: " + ttl + "]";
        if (ttl < 600) return red(text);
        if (ttl < 3600) return yellow(text);
        return green(text);
    }

    private String formatLatencyColored(Duration d) {
        String text = formatLatency(d);
        double ms = d.toNanos() / 1_000_000.0;
        if (ms < 50) return green(text);
        if (ms < 200) return yellow(text);
        return red(text);
    }

    private String formatAddresses(Set<InetAddress> addresses) {
        return addresses.stream()
                .map(InetAddress::getHostAddress)
                .collect(Collectors.joining(", "));
    }

    // --- Color helpers ---

    private String color(String code, String text) {
        if (!useColor) return text;
        return code + text + RESET;
    }

    private String bold(String text) { return color(BOLD, text); }
    private String red(String text) { return color(RED, text); }
    private String green(String text) { return color(GREEN, text); }
    private String yellow(String text) { return color(YELLOW, text); }
    private String blue(String text) { return color(BLUE, text); }
    private String cyan(String text) { return color(CYAN, text); }
    private String magenta(String text) { return color(MAGENTA, text); }
    private String gray(String text) { return color(GRAY, text); }

    private void println(String text) {
        System.out.println(text);
    }
}
