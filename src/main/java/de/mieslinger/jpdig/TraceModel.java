package de.mieslinger.jpdig;

import org.xbill.DNS.Message;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;

/**
 * All model records used throughout the trace operation.
 */
public final class TraceModel {

    private TraceModel() {}

    /** Severity levels for validation messages. */
    public enum Severity { OK, WARN, ERROR }

    /** Result of a single DNS query to one server IP. */
    public record QueryResult(
            InetAddress server,
            String serverName,
            Message response,
            Duration latency,
            String protocol,
            boolean tcpFallback,
            String nsid,
            String error
    ) {
        public boolean isSuccess() {
            return error == null && response != null;
        }
    }

    /** Result of resolving an NS name to an A or AAAA address. */
    public record NsAddressRecord(
            String nsName,
            String recordType,
            InetAddress address,
            long ttl,
            Duration latency,
            String resolvedVia,
            boolean fromGlue
    ) {}

    /** A validation message with severity. */
    public record ValidationMessage(
            Severity severity,
            String message
    ) {}

    /** Information about a single server query at a trace level. */
    public record ServerQueryDetail(
            String serverName,
            InetAddress serverAddress,
            Duration latency,
            String protocol,
            boolean tcpFallback,
            String nsid,
            String error,
            Set<String> nsRecords,
            long nsRecordTtl
    ) {}

    /** Glue validation result for one NS name. */
    public record GlueValidation(
            String nsName,
            Set<InetAddress> glueAddresses,
            Set<InetAddress> authoritativeAddresses,
            boolean matches
    ) {}

    /** Statistics for one trace level. */
    public record LevelStats(
            int totalQueries,
            int udpQueries,
            int tcpQueries,
            int tcpFallbacks,
            int failedQueries,
            Duration minLatency,
            Duration maxLatency
    ) {
        public static LevelStats compute(List<ServerQueryDetail> queries) {
            int total = queries.size();
            int udp = 0, tcp = 0, fallbacks = 0, failed = 0;
            Duration min = Duration.ofDays(1);
            Duration max = Duration.ZERO;

            for (var q : queries) {
                if (q.error() != null) {
                    failed++;
                    continue;
                }
                if ("UDP".equals(q.protocol())) udp++;
                else tcp++;
                if (q.tcpFallback()) fallbacks++;
                if (q.latency().compareTo(min) < 0) min = q.latency();
                if (q.latency().compareTo(max) > 0) max = q.latency();
            }
            if (total == failed) {
                min = Duration.ZERO;
                max = Duration.ZERO;
            }
            return new LevelStats(total, udp, tcp, fallbacks, failed, min, max);
        }
    }

    /** One level of the DNS trace. */
    public record TraceLevel(
            String zoneName,
            int levelNumber,

            // Delegation info (from parent zone's referral)
            Set<String> delegationNs,
            long delegationNsTtl,
            List<ServerQueryDetail> delegationQueries,
            Map<String, Set<InetAddress>> glueRecords,

            // NS name resolution
            List<NsAddressRecord> nsResolutions,

            // Authoritative info (from querying this zone's own servers)
            Set<String> authoritativeNs,
            long authoritativeNsTtl,
            List<ServerQueryDetail> authoritativeQueries,
            Map<String, Set<InetAddress>> authoritativeAddresses,

            // Delegation NS consistency across queried servers
            Map<Set<String>, List<String>> delegationNsVariants,
            Map<Set<String>, List<String>> authoritativeNsVariants,

            // Validations
            List<ValidationMessage> validations,
            List<GlueValidation> glueValidations,

            // Stats
            LevelStats delegationStats,
            LevelStats authoritativeStats,

            // CNAME detected at this level (null if none)
            String cnameTarget,

            // Whether this is the final (authoritative) level for the target
            boolean isFinal
    ) {}

    /** Overall trace result. */
    public record TraceResult(
            String domain,
            List<TraceLevel> levels,
            boolean ipv4Available,
            boolean ipv6Available,
            Duration totalDuration,
            int totalQueries,
            int nsQueries,
            int aQueries,
            int aaaaQueries
    ) {}

    /** Connectivity information. */
    public record ConnectivityInfo(
            boolean ipv4Available,
            boolean ipv6Available
    ) {}
}
