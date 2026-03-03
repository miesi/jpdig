package de.mieslinger.jpdig;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Core trace engine that performs iterative DNS resolution
 * following the actual referral chain (like dig +trace),
 * with parallel queries and validation at each level.
 */
public class TraceEngine {

    private static final int MAX_LEVELS = 20;

    private final DnsClient client;
    private final TraceModel.ConnectivityInfo connectivity;
    private final Consumer<String> progress;
    private final int timeoutMs;

    // Query counters by type
    private int nsQueryCount;
    private int aQueryCount;
    private int aaaaQueryCount;

    public TraceEngine(DnsClient client, TraceModel.ConnectivityInfo connectivity, int timeoutMs) {
        this(client, connectivity, msg -> {}, timeoutMs);
    }

    public TraceEngine(DnsClient client, TraceModel.ConnectivityInfo connectivity,
                       Consumer<String> progress, int timeoutMs) {
        this.client = client;
        this.connectivity = connectivity;
        this.progress = progress;
        this.timeoutMs = timeoutMs;
    }

    /**
     * Perform a full DNS trace for the given domain by following the
     * actual referral chain from root servers down.
     */
    public TraceModel.TraceResult trace(String domain) {
        long startTime = System.nanoTime();
        nsQueryCount = 0;
        aQueryCount = 0;
        aaaaQueryCount = 0;

        Name target;
        try {
            target = Name.fromString(domain);
        } catch (TextParseException e) {
            throw new RuntimeException("Invalid domain name: " + domain, e);
        }

        List<TraceModel.TraceLevel> levels = new ArrayList<>();

        // Start with root servers
        Map<InetAddress, String> currentServerMap = RootHints.getAddressToNameMap();
        List<InetAddress> currentServers = filterByConnectivity(
                new ArrayList<>(currentServerMap.keySet()));

        int levelIdx = 0;
        Set<Name> seenReferralZones = new HashSet<>();

        while (levelIdx < MAX_LEVELS) {
            // --- Query current servers for target NS ---
            String serverDesc = levelIdx == 0 ? "root servers"
                    : currentServers.size() + " servers";
            progress.accept("Level " + (levelIdx + 1) + ": Querying " + serverDesc
                    + " for " + target + " NS...");
            List<TraceModel.QueryResult> queryResults =
                    parallelQuery(currentServers, currentServerMap, target, Type.NS);
            long successCount = queryResults.stream().filter(TraceModel.QueryResult::isSuccess).count();
            long failCount = queryResults.size() - successCount;
            progress.accept("Level " + (levelIdx + 1) + ": Got " + successCount + " responses"
                    + (failCount > 0 ? ", " + failCount + " failed" : ""));

            // Abort early if ALL queries failed - likely a timeout issue
            if (successCount == 0 && !queryResults.isEmpty()) {
                List<TraceModel.ValidationMessage> validations = new ArrayList<>();
                validations.add(new TraceModel.ValidationMessage(
                        TraceModel.Severity.ERROR,
                        "All " + queryResults.size() + " queries failed at this level. "
                                + "All servers likely exceeded the " + timeoutMs + "ms timeout. "
                                + "Try increasing the timeout, e.g.: --timeout "
                                + Math.max(timeoutMs * 5, 500)));
                List<TraceModel.ServerQueryDetail> failedDetails = buildQueryDetails(queryResults);
                TraceModel.LevelStats stats = TraceModel.LevelStats.compute(failedDetails);
                TraceModel.TraceLevel errorLevel = new TraceModel.TraceLevel(
                        "?", levelIdx,
                        Set.of(), 0, failedDetails, Map.of(),
                        List.of(),
                        Set.of(), 0, List.of(), Map.of(),
                        Map.of(), Map.of(),
                        validations, List.of(),
                        stats, null,
                        null, true
                );
                levels.add(errorLevel);
                break;
            }

            // Analyze all responses
            ResponseAnalysis analysis = analyzeResponses(queryResults, target);

            List<TraceModel.ServerQueryDetail> delegationQueryDetails =
                    buildQueryDetails(queryResults);

            if (analysis.isAuthoritative) {
                // Authoritative response - this is the final level
                // Could be an NS answer, CNAME, or NODATA
                TraceModel.TraceLevel finalLevel = buildFinalLevel(
                        levelIdx, target, analysis, delegationQueryDetails, queryResults);
                levels.add(finalLevel);
                break;

            } else if (!analysis.referralNs.isEmpty()) {
                // Referral - extract delegation info and continue
                Name referralZone = analysis.referralZone;
                Set<String> delegationNs = analysis.referralNs;
                long delegationTtl = analysis.referralTtl;
                Map<String, Set<InetAddress>> glueRecords = analysis.glueRecords;
                Map<Set<String>, List<String>> delegationVariants = analysis.nsVariants;

                // Detect referral loop: same zone referred again
                if (!seenReferralZones.add(referralZone)) {
                    List<TraceModel.ValidationMessage> validations = new ArrayList<>();
                    validations.add(new TraceModel.ValidationMessage(
                            TraceModel.Severity.ERROR,
                            "Referral loop detected: " + referralZone
                                    + " was already referred at a previous level. "
                                    + "The nameservers for this zone do not provide "
                                    + "an authoritative answer and keep referring back "
                                    + "to the same zone."));
                    TraceModel.LevelStats stats =
                            TraceModel.LevelStats.compute(delegationQueryDetails);
                    TraceModel.TraceLevel errorLevel = new TraceModel.TraceLevel(
                            referralZone.toString(), levelIdx,
                            delegationNs, delegationTtl, delegationQueryDetails, glueRecords,
                            List.of(),
                            Set.of(), 0, List.of(), Map.of(),
                            delegationVariants, Map.of(),
                            validations, List.of(),
                            stats, null,
                            null, true
                    );
                    levels.add(errorLevel);
                    break;
                }

                // --- Resolve NS names to IPs ---
                progress.accept("Level " + (levelIdx + 1) + ": Referral to " + referralZone
                        + " (" + delegationNs.size() + " NS)");
                List<TraceModel.NsAddressRecord> nsResolutions = new ArrayList<>();
                Map<String, Set<InetAddress>> resolvedAddresses = new HashMap<>();

                for (String nsName : delegationNs) {
                    progress.accept("Level " + (levelIdx + 1) + ": Resolving " + nsName + "...");
                    Set<InetAddress> glue = glueRecords.getOrDefault(nsName, Set.of());

                    if (!glue.isEmpty()) {
                        for (InetAddress addr : glue) {
                            String recType = (addr instanceof Inet4Address) ? "A" : "AAAA";
                            nsResolutions.add(new TraceModel.NsAddressRecord(
                                    nsName, recType, addr, 0, Duration.ZERO, "glue", true));
                            resolvedAddresses.computeIfAbsent(nsName, k -> new LinkedHashSet<>())
                                    .add(addr);
                        }
                    }

                    // Also resolve authoritatively
                    List<TraceModel.NsAddressRecord> resolved =
                            resolveNsName(nsName, currentServers, currentServerMap);
                    nsResolutions.addAll(resolved);

                    for (var rec : resolved) {
                        resolvedAddresses.computeIfAbsent(nsName, k -> new LinkedHashSet<>())
                                .add(rec.address());
                    }
                }

                // Combine all IPs
                List<InetAddress> zoneServerIps = new ArrayList<>();
                Map<InetAddress, String> zoneServerMap = new HashMap<>();
                for (var entry : resolvedAddresses.entrySet()) {
                    for (InetAddress addr : entry.getValue()) {
                        if (!zoneServerIps.contains(addr)) {
                            zoneServerIps.add(addr);
                            zoneServerMap.put(addr, entry.getKey());
                        }
                    }
                }
                zoneServerIps = filterByConnectivity(zoneServerIps);

                // --- Query zone's own servers for authoritative NS ---
                Set<String> authoritativeNs = new LinkedHashSet<>();
                long authoritativeTtl = 0;
                List<TraceModel.ServerQueryDetail> authQueryDetails = new ArrayList<>();
                Map<Set<String>, List<String>> authVariants = new LinkedHashMap<>();
                Map<String, Set<InetAddress>> authoritativeAddresses = new HashMap<>();

                if (!zoneServerIps.isEmpty()) {
                    progress.accept("Level " + (levelIdx + 1) + ": Querying " + zoneServerIps.size()
                            + " authoritative servers for " + referralZone + " NS...");
                    List<TraceModel.QueryResult> authResults =
                            parallelQuery(zoneServerIps, zoneServerMap, referralZone, Type.NS);

                    long authSuccessCount = authResults.stream()
                            .filter(TraceModel.QueryResult::isSuccess).count();

                    // If ALL authoritative queries failed, abort early
                    if (authSuccessCount == 0 && !authResults.isEmpty()) {
                        List<TraceModel.ValidationMessage> validations = new ArrayList<>();
                        validations.add(new TraceModel.ValidationMessage(
                                TraceModel.Severity.ERROR,
                                "All " + authResults.size() + " authoritative queries to "
                                        + referralZone + " failed. "
                                        + "All servers likely exceeded the " + timeoutMs + "ms timeout. "
                                        + "Try increasing the timeout, e.g.: --timeout "
                                        + Math.max(timeoutMs * 5, 500)));
                        authQueryDetails = buildQueryDetails(authResults);
                        TraceModel.LevelStats delegationStats =
                                TraceModel.LevelStats.compute(buildQueryDetails(queryResults));
                        TraceModel.LevelStats authStats =
                                TraceModel.LevelStats.compute(authQueryDetails);
                        TraceModel.TraceLevel errorLevel = new TraceModel.TraceLevel(
                                referralZone.toString(), levelIdx,
                                delegationNs, delegationTtl,
                                buildQueryDetails(queryResults), glueRecords,
                                nsResolutions,
                                Set.of(), 0, authQueryDetails, Map.of(),
                                delegationVariants, Map.of(),
                                validations, List.of(),
                                delegationStats, authStats,
                                null, true
                        );
                        levels.add(errorLevel);
                        break;
                    }

                    for (var result : authResults) {
                        if (!result.isSuccess()) continue;
                        Message msg = result.response();

                        Set<String> nsSet = extractNsFromAnswer(msg);
                        if (!nsSet.isEmpty()) {
                            authoritativeNs.addAll(nsSet);
                            if (authoritativeTtl == 0) {
                                authoritativeTtl = extractNsAnswerTtl(msg);
                            }
                            String serverLabel = result.serverName() != null
                                    ? result.serverName() : result.server().getHostAddress();
                            authVariants.computeIfAbsent(nsSet, k -> new ArrayList<>())
                                    .add(serverLabel);
                        }

                        extractGlue(msg, authoritativeAddresses);
                    }

                    // Resolve A/AAAA for NS names from authoritative servers
                    for (String nsName : authoritativeNs) {
                        List<TraceModel.NsAddressRecord> authResolved =
                                resolveNsNameFromServers(nsName, zoneServerIps, zoneServerMap);
                        for (var rec : authResolved) {
                            authoritativeAddresses.computeIfAbsent(nsName, k -> new LinkedHashSet<>())
                                    .add(rec.address());
                        }
                    }

                    authQueryDetails = buildQueryDetails(authResults);
                }

                // --- Validation ---
                List<TraceModel.ValidationMessage> validations = new ArrayList<>();
                List<TraceModel.GlueValidation> glueValidations = new ArrayList<>();

                Validator.compareNsSets(delegationNs, authoritativeNs,
                        referralZone.toString(), validations);
                Validator.compareTtls(delegationTtl, authoritativeTtl,
                        referralZone.toString(), validations);
                Validator.validateTtl("delegation NS", delegationTtl, validations);
                Validator.validateTtl("authoritative NS", authoritativeTtl, validations);

                // Glue validation
                for (String nsName : glueRecords.keySet()) {
                    Set<InetAddress> glue = glueRecords.get(nsName);
                    Set<InetAddress> auth = authoritativeAddresses.getOrDefault(nsName, Set.of());
                    if (!glue.isEmpty() && !auth.isEmpty()) {
                        boolean matches = glue.equals(auth);
                        glueValidations.add(new TraceModel.GlueValidation(
                                nsName, glue, auth, matches));
                        if (!matches) {
                            validations.add(new TraceModel.ValidationMessage(
                                    TraceModel.Severity.WARN,
                                    "Glue mismatch for " + nsName
                                            + ": glue=" + formatAddresses(glue)
                                            + " auth=" + formatAddresses(auth)));
                        }
                    }
                }

                if (delegationVariants.size() > 1) {
                    validations.add(new TraceModel.ValidationMessage(
                            TraceModel.Severity.WARN,
                            "Delegation servers disagree on NS set for " + referralZone));
                }
                if (authVariants.size() > 1) {
                    validations.add(new TraceModel.ValidationMessage(
                            TraceModel.Severity.WARN,
                            "Authoritative servers disagree on NS set for " + referralZone));
                }

                TraceModel.LevelStats delegationStats =
                        TraceModel.LevelStats.compute(delegationQueryDetails);
                TraceModel.LevelStats authStats =
                        TraceModel.LevelStats.compute(authQueryDetails);

                // If referral zone IS the target, this is the final level
                boolean isFinalLevel = referralZone.equals(target);

                TraceModel.TraceLevel level = new TraceModel.TraceLevel(
                        referralZone.toString(), levelIdx,
                        delegationNs, delegationTtl, delegationQueryDetails, glueRecords,
                        nsResolutions,
                        authoritativeNs, authoritativeTtl, authQueryDetails, authoritativeAddresses,
                        delegationVariants, authVariants,
                        validations, glueValidations,
                        delegationStats, authStats,
                        null, isFinalLevel
                );
                levels.add(level);

                if (isFinalLevel) {
                    break;
                }

                // Move to next level: use the zone's servers
                currentServers = zoneServerIps;
                currentServerMap = zoneServerMap;

            } else {
                // No referral, no authoritative answer - something went wrong
                List<TraceModel.ValidationMessage> validations = new ArrayList<>();
                validations.add(new TraceModel.ValidationMessage(
                        TraceModel.Severity.ERROR,
                        "No referral or authoritative response received"));
                TraceModel.LevelStats stats = TraceModel.LevelStats.compute(delegationQueryDetails);
                TraceModel.TraceLevel errorLevel = new TraceModel.TraceLevel(
                        "?", levelIdx,
                        Set.of(), 0, delegationQueryDetails, Map.of(),
                        List.of(),
                        Set.of(), 0, List.of(), Map.of(),
                        Map.of(), Map.of(),
                        validations, List.of(),
                        stats, null,
                        null, true
                );
                levels.add(errorLevel);
                break;
            }

            levelIdx++;
        }

        int totalQueries = nsQueryCount + aQueryCount + aaaaQueryCount;
        Duration totalDuration = Duration.ofNanos(System.nanoTime() - startTime);
        return new TraceModel.TraceResult(domain, levels,
                connectivity.ipv4Available(), connectivity.ipv6Available(),
                totalDuration, totalQueries, nsQueryCount, aQueryCount, aaaaQueryCount);
    }

    // ---- Response Analysis ----

    /**
     * Analyze all query responses to determine if we got a referral,
     * authoritative answer, CNAME, or error.
     */
    private ResponseAnalysis analyzeResponses(List<TraceModel.QueryResult> results, Name target) {
        ResponseAnalysis analysis = new ResponseAnalysis();

        for (var result : results) {
            if (!result.isSuccess()) continue;
            Message msg = result.response();
            boolean aa = msg.getHeader().getFlag(Flags.AA);

            // Check for CNAME in ANSWER section
            String cname = extractCname(msg, target);
            if (cname != null) {
                analysis.cnameTarget = cname;
                analysis.isAuthoritative = true;
            }

            if (aa) {
                // Authoritative answer
                analysis.isAuthoritative = true;
                Set<String> nsSet = extractNsFromAnswer(msg);
                if (!nsSet.isEmpty()) {
                    analysis.authoritativeNs.addAll(nsSet);
                    if (analysis.authoritativeTtl == 0) {
                        analysis.authoritativeTtl = extractNsAnswerTtl(msg);
                    }
                    String label = result.serverName() != null
                            ? result.serverName() : result.server().getHostAddress();
                    analysis.authNsVariants
                            .computeIfAbsent(nsSet, k -> new ArrayList<>()).add(label);
                }
            } else {
                // Non-authoritative - look for referral in AUTHORITY section
                for (org.xbill.DNS.Record rec : msg.getSection(Section.AUTHORITY)) {
                    if (rec instanceof NSRecord nsRec) {
                        Name zone = rec.getName();
                        // Accept referral only if the zone is a parent/match of target
                        if (target.subdomain(zone)) {
                            analysis.referralZone = zone;
                            analysis.referralNs.add(nsRec.getTarget().toString());
                            if (analysis.referralTtl == 0) {
                                analysis.referralTtl = rec.getTTL();
                            }
                        }
                    }
                }

                // Track NS set variants per server
                if (!analysis.referralNs.isEmpty()) {
                    Set<String> nsSetForThisServer = new LinkedHashSet<>();
                    for (org.xbill.DNS.Record rec : msg.getSection(Section.AUTHORITY)) {
                        if (rec instanceof NSRecord nsRec) {
                            if (rec.getName().equals(analysis.referralZone)) {
                                nsSetForThisServer.add(nsRec.getTarget().toString());
                            }
                        }
                    }
                    if (!nsSetForThisServer.isEmpty()) {
                        String label = result.serverName() != null
                                ? result.serverName() : result.server().getHostAddress();
                        analysis.nsVariants
                                .computeIfAbsent(nsSetForThisServer, k -> new ArrayList<>())
                                .add(label);
                    }
                }

                // Extract glue
                extractGlue(msg, analysis.glueRecords);
            }
        }

        return analysis;
    }

    /** Mutable container for response analysis results. */
    private static class ResponseAnalysis {
        boolean isAuthoritative = false;
        Name referralZone = null;
        Set<String> referralNs = new LinkedHashSet<>();
        long referralTtl = 0;
        Map<String, Set<InetAddress>> glueRecords = new HashMap<>();
        Map<Set<String>, List<String>> nsVariants = new LinkedHashMap<>();

        Set<String> authoritativeNs = new LinkedHashSet<>();
        long authoritativeTtl = 0;
        Map<Set<String>, List<String>> authNsVariants = new LinkedHashMap<>();

        String cnameTarget = null;
    }

    /**
     * Build the final (authoritative) level of the trace.
     */
    private TraceModel.TraceLevel buildFinalLevel(
            int levelIdx,
            Name target,
            ResponseAnalysis analysis,
            List<TraceModel.ServerQueryDetail> delegationQueryDetails,
            List<TraceModel.QueryResult> queryResults) {

        List<TraceModel.ValidationMessage> validations = new ArrayList<>();

        String zoneName = target.toString();

        // If we have authoritative NS from the AA response itself
        Set<String> authNs = analysis.authoritativeNs;
        long authTtl = analysis.authoritativeTtl;

        if (analysis.cnameTarget != null) {
            validations.add(new TraceModel.ValidationMessage(
                    TraceModel.Severity.OK,
                    "CNAME detected: " + analysis.cnameTarget));
            // Determine zone name from the server context
            // The zone is whatever zone the AA server is authoritative for
        }

        if (!authNs.isEmpty()) {
            Validator.validateTtl("authoritative NS", authTtl, validations);
        }

        TraceModel.LevelStats stats = TraceModel.LevelStats.compute(delegationQueryDetails);

        return new TraceModel.TraceLevel(
                zoneName, levelIdx,
                Set.of(), 0, delegationQueryDetails, Map.of(),
                List.of(),
                authNs, authTtl, List.of(), Map.of(),
                Map.of(), analysis.authNsVariants,
                validations, List.of(),
                stats, null,
                analysis.cnameTarget, true
        );
    }

    // ---- DNS extraction helpers ----

    /** Extract CNAME target from ANSWER section. */
    private String extractCname(Message msg, Name queryName) {
        for (org.xbill.DNS.Record rec : msg.getSection(Section.ANSWER)) {
            if (rec instanceof CNAMERecord cnameRec) {
                if (rec.getName().equals(queryName)) {
                    return cnameRec.getTarget().toString();
                }
            }
        }
        return null;
    }

    /** Extract NS records from the ANSWER section. */
    private Set<String> extractNsFromAnswer(Message msg) {
        Set<String> ns = new LinkedHashSet<>();
        for (org.xbill.DNS.Record rec : msg.getSection(Section.ANSWER)) {
            if (rec instanceof NSRecord nsRec) {
                ns.add(nsRec.getTarget().toString());
            }
        }
        return ns;
    }

    /** Extract NS TTL from ANSWER section. */
    private long extractNsAnswerTtl(Message msg) {
        for (org.xbill.DNS.Record rec : msg.getSection(Section.ANSWER)) {
            if (rec instanceof NSRecord) {
                return rec.getTTL();
            }
        }
        return 0;
    }

    /** Extract glue records (A/AAAA) from ADDITIONAL section. */
    private void extractGlue(Message msg, Map<String, Set<InetAddress>> glue) {
        for (org.xbill.DNS.Record rec : msg.getSection(Section.ADDITIONAL)) {
            if (rec instanceof ARecord aRec) {
                glue.computeIfAbsent(rec.getName().toString(), k -> new LinkedHashSet<>())
                        .add(aRec.getAddress());
            } else if (rec instanceof AAAARecord aaaaRec) {
                glue.computeIfAbsent(rec.getName().toString(), k -> new LinkedHashSet<>())
                        .add(aaaaRec.getAddress());
            }
        }
    }

    // ---- Parallel query ----

    /** Query multiple servers in parallel using virtual threads. */
    private List<TraceModel.QueryResult> parallelQuery(
            List<InetAddress> servers,
            Map<InetAddress, String> nameMap,
            Name queryName,
            int queryType) {

        // Track query counts by type
        int count = servers.size();
        switch (queryType) {
            case Type.NS -> nsQueryCount += count;
            case Type.A -> aQueryCount += count;
            case Type.AAAA -> aaaaQueryCount += count;
        }

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<TraceModel.QueryResult>> futures = new ArrayList<>();
            for (InetAddress server : servers) {
                String serverName = nameMap.getOrDefault(server, server.getHostAddress());
                futures.add(executor.submit(
                        () -> client.query(server, serverName, queryName, queryType)));
            }

            List<TraceModel.QueryResult> results = new ArrayList<>();
            for (var future : futures) {
                try {
                    results.add(future.get(30, TimeUnit.SECONDS));
                } catch (Exception e) {
                    // Individual failures are captured in QueryResult
                }
            }
            return results;
        }
    }

    // ---- NS name resolution ----

    /** Resolve an NS name to A and AAAA records independently. */
    private List<TraceModel.NsAddressRecord> resolveNsName(
            String nsName,
            List<InetAddress> currentServers,
            Map<InetAddress, String> currentServerMap) {

        List<TraceModel.NsAddressRecord> results = new ArrayList<>();
        Name name;
        try {
            name = Name.fromString(nsName);
        } catch (TextParseException e) {
            return results;
        }

        List<InetAddress> rootServers = filterByConnectivity(
                new ArrayList<>(RootHints.getAddressToNameMap().keySet()));
        Map<InetAddress, String> rootMap = RootHints.getAddressToNameMap();

        // Resolve A and AAAA independently, each with its own iterative fallback
        if (connectivity.ipv4Available()) {
            List<TraceModel.NsAddressRecord> v4 = new ArrayList<>();
            resolveType(name, Type.A, "A", nsName, currentServers, currentServerMap, v4);
            if (v4.isEmpty()) {
                resolveIterativelyForType(name, nsName, rootServers, rootMap, v4, Type.A, 0);
            }
            results.addAll(v4);
        }
        if (connectivity.ipv6Available()) {
            List<TraceModel.NsAddressRecord> v6 = new ArrayList<>();
            resolveType(name, Type.AAAA, "AAAA", nsName, currentServers, currentServerMap, v6);
            if (v6.isEmpty()) {
                resolveIterativelyForType(name, nsName, rootServers, rootMap, v6, Type.AAAA, 0);
            }
            results.addAll(v6);
        }

        return results;
    }

    /** Resolve an NS name from specific servers. */
    private List<TraceModel.NsAddressRecord> resolveNsNameFromServers(
            String nsName,
            List<InetAddress> servers,
            Map<InetAddress, String> serverMap) {

        List<TraceModel.NsAddressRecord> results = new ArrayList<>();
        Name name;
        try {
            name = Name.fromString(nsName);
        } catch (TextParseException e) {
            return results;
        }

        if (connectivity.ipv4Available()) {
            resolveType(name, Type.A, "A", nsName, servers, serverMap, results);
        }
        if (connectivity.ipv6Available()) {
            resolveType(name, Type.AAAA, "AAAA", nsName, servers, serverMap, results);
        }

        return results;
    }

    private void resolveType(Name name, int type, String typeName, String nsName,
                             List<InetAddress> servers, Map<InetAddress, String> serverMap,
                             List<TraceModel.NsAddressRecord> results) {
        List<InetAddress> queryServers = servers.size() > 3
                ? servers.subList(0, 3) : servers;

        List<TraceModel.QueryResult> queryResults =
                parallelQuery(queryServers, serverMap, name, type);

        Set<InetAddress> seen = new HashSet<>();
        for (var qr : queryResults) {
            if (!qr.isSuccess()) continue;
            Message msg = qr.response();

            for (org.xbill.DNS.Record rec : msg.getSection(Section.ANSWER)) {
                InetAddress addr = null;
                if (rec instanceof ARecord aRec && type == Type.A) {
                    addr = aRec.getAddress();
                } else if (rec instanceof AAAARecord aaaaRec && type == Type.AAAA) {
                    addr = aaaaRec.getAddress();
                }
                if (addr != null && seen.add(addr)) {
                    String via = qr.serverName() != null
                            ? qr.serverName() : qr.server().getHostAddress();
                    results.add(new TraceModel.NsAddressRecord(
                            nsName, typeName, addr, rec.getTTL(), qr.latency(), via, false));
                }
            }
        }
    }

    /**
     * Iteratively resolve a name for a single record type,
     * following referrals from the given servers.
     */
    private void resolveIterativelyForType(Name name, String nsName,
                                           List<InetAddress> servers,
                                           Map<InetAddress, String> serverMap,
                                           List<TraceModel.NsAddressRecord> results,
                                           int type, int depth) {
        if (depth > 10) return;

        List<InetAddress> queryServers = servers.size() > 3
                ? servers.subList(0, 3) : servers;

        String typeName = (type == Type.A) ? "A" : "AAAA";

        List<TraceModel.QueryResult> queryResults =
                parallelQuery(queryServers, serverMap, name, type);

        for (var qr : queryResults) {
            if (!qr.isSuccess()) continue;
            Message msg = qr.response();

            // Check ANSWER section for address records
            for (org.xbill.DNS.Record rec : msg.getSection(Section.ANSWER)) {
                InetAddress addr = null;
                if (rec instanceof ARecord aRec && type == Type.A) addr = aRec.getAddress();
                else if (rec instanceof AAAARecord aaaaRec && type == Type.AAAA) addr = aaaaRec.getAddress();

                if (addr != null) {
                    results.add(new TraceModel.NsAddressRecord(
                            nsName, typeName, addr, rec.getTTL(), qr.latency(), qr.serverName(), false));
                }
            }

            if (!results.isEmpty()) return;

            // No answer - follow referral if present
            Map<String, Set<InetAddress>> referralGlue = new HashMap<>();
            extractGlue(msg, referralGlue);

            List<InetAddress> nextServers = new ArrayList<>();
            Map<InetAddress, String> nextMap = new HashMap<>();
            for (var entry : referralGlue.entrySet()) {
                for (InetAddress addr : entry.getValue()) {
                    nextServers.add(addr);
                    nextMap.put(addr, entry.getKey());
                }
            }
            nextServers = filterByConnectivity(nextServers);
            if (!nextServers.isEmpty()) {
                resolveIterativelyForType(name, nsName, nextServers, nextMap, results, type, depth + 1);
                if (!results.isEmpty()) return;
            }
        }
    }

    // ---- Helpers ----

    /** Filter addresses by available connectivity. */
    private List<InetAddress> filterByConnectivity(List<InetAddress> addresses) {
        return addresses.stream()
                .filter(addr -> {
                    if (addr instanceof Inet4Address) return connectivity.ipv4Available();
                    if (addr instanceof Inet6Address) return connectivity.ipv6Available();
                    return true;
                })
                .collect(Collectors.toCollection(ArrayList::new));
    }

    /** Build ServerQueryDetail list from query results. */
    private List<TraceModel.ServerQueryDetail> buildQueryDetails(
            List<TraceModel.QueryResult> results) {
        List<TraceModel.ServerQueryDetail> details = new ArrayList<>();
        for (var r : results) {
            Set<String> ns = new LinkedHashSet<>();
            long ttl = 0;

            if (r.isSuccess()) {
                Message msg = r.response();
                for (org.xbill.DNS.Record rec : msg.getSection(Section.AUTHORITY)) {
                    if (rec instanceof NSRecord nsRec) {
                        ns.add(nsRec.getTarget().toString());
                        ttl = rec.getTTL();
                    }
                }
                if (ns.isEmpty()) {
                    for (org.xbill.DNS.Record rec : msg.getSection(Section.ANSWER)) {
                        if (rec instanceof NSRecord nsRec) {
                            ns.add(nsRec.getTarget().toString());
                            ttl = rec.getTTL();
                        }
                    }
                }
            }

            details.add(new TraceModel.ServerQueryDetail(
                    r.serverName(), r.server(), r.latency(), r.protocol(),
                    r.tcpFallback(), r.nsid(), r.error(), ns, ttl));
        }
        return details;
    }

    private String formatAddresses(Set<InetAddress> addresses) {
        return addresses.stream()
                .map(InetAddress::getHostAddress)
                .collect(Collectors.joining(", "));
    }
}
