package de.mieslinger.jpdig;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;

import java.net.InetAddress;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * JSON output formatter for trace results.
 * Converts the trace model into a clean JSON representation.
 */
public class JsonOutput {

    public void print(TraceModel.TraceResult result) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);

            Map<String, Object> json = buildJson(result);
            System.out.println(mapper.writeValueAsString(json));
        } catch (Exception e) {
            System.err.println("Error generating JSON output: " + e.getMessage());
        }
    }

    private Map<String, Object> buildJson(TraceModel.TraceResult result) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("domain", result.domain());
        json.put("ipv4Available", result.ipv4Available());
        json.put("ipv6Available", result.ipv6Available());
        json.put("totalDurationMs", durationMs(result.totalDuration()));
        json.put("totalQueries", result.totalQueries());
        json.put("nsQueries", result.nsQueries());
        json.put("aQueries", result.aQueries());
        json.put("aaaaQueries", result.aaaaQueries());

        List<Map<String, Object>> levels = new ArrayList<>();
        for (var level : result.levels()) {
            levels.add(buildLevelJson(level));
        }
        json.put("levels", levels);

        return json;
    }

    private Map<String, Object> buildLevelJson(TraceModel.TraceLevel level) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("zone", level.zoneName());
        json.put("level", level.levelNumber() + 1);
        json.put("isFinal", level.isFinal());
        if (level.cnameTarget() != null) {
            json.put("cnameTarget", level.cnameTarget());
        }

        // Delegation
        Map<String, Object> delegation = new LinkedHashMap<>();
        delegation.put("ns", new ArrayList<>(level.delegationNs()));
        delegation.put("ttl", level.delegationNsTtl());
        delegation.put("queries", buildQueryListJson(level.delegationQueries()));
        if (level.delegationStats() != null) {
            delegation.put("stats", buildStatsJson(level.delegationStats()));
        }
        if (level.delegationNsVariants() != null && level.delegationNsVariants().size() > 1) {
            delegation.put("variants", buildVariantsJson(level.delegationNsVariants()));
        }
        json.put("delegation", delegation);

        // Glue
        if (!level.glueRecords().isEmpty()) {
            Map<String, List<String>> glue = new LinkedHashMap<>();
            for (var entry : level.glueRecords().entrySet()) {
                glue.put(entry.getKey(), entry.getValue().stream()
                        .map(InetAddress::getHostAddress).toList());
            }
            json.put("glue", glue);
        }

        // NS Resolutions
        if (!level.nsResolutions().isEmpty()) {
            List<Map<String, Object>> resolutions = new ArrayList<>();
            for (var res : level.nsResolutions()) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("name", res.nsName());
                r.put("type", res.recordType());
                r.put("address", res.address().getHostAddress());
                r.put("ttl", res.ttl());
                r.put("latencyMs", durationMs(res.latency()));
                r.put("via", res.resolvedVia());
                r.put("fromGlue", res.fromGlue());
                resolutions.add(r);
            }
            json.put("nsResolutions", resolutions);
        }

        // Authoritative
        Map<String, Object> authoritative = new LinkedHashMap<>();
        authoritative.put("ns", new ArrayList<>(level.authoritativeNs()));
        authoritative.put("ttl", level.authoritativeNsTtl());
        authoritative.put("queries", buildQueryListJson(level.authoritativeQueries()));
        if (level.authoritativeStats() != null) {
            authoritative.put("stats", buildStatsJson(level.authoritativeStats()));
        }
        if (level.authoritativeNsVariants() != null && level.authoritativeNsVariants().size() > 1) {
            authoritative.put("variants", buildVariantsJson(level.authoritativeNsVariants()));
        }
        json.put("authoritative", authoritative);

        // Glue Validation
        if (!level.glueValidations().isEmpty()) {
            List<Map<String, Object>> gvList = new ArrayList<>();
            for (var gv : level.glueValidations()) {
                Map<String, Object> g = new LinkedHashMap<>();
                g.put("nsName", gv.nsName());
                g.put("matches", gv.matches());
                g.put("glueAddresses", gv.glueAddresses().stream()
                        .map(InetAddress::getHostAddress).toList());
                g.put("authoritativeAddresses", gv.authoritativeAddresses().stream()
                        .map(InetAddress::getHostAddress).toList());
                gvList.add(g);
            }
            json.put("glueValidation", gvList);
        }

        // Validations
        if (!level.validations().isEmpty()) {
            List<Map<String, Object>> valList = new ArrayList<>();
            for (var v : level.validations()) {
                Map<String, Object> vm = new LinkedHashMap<>();
                vm.put("severity", v.severity().name());
                vm.put("message", v.message());
                valList.add(vm);
            }
            json.put("validations", valList);
        }

        return json;
    }

    private List<Map<String, Object>> buildQueryListJson(List<TraceModel.ServerQueryDetail> queries) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (var q : queries) {
            Map<String, Object> qj = new LinkedHashMap<>();
            qj.put("server", q.serverAddress().getHostAddress());
            qj.put("serverName", q.serverName());
            qj.put("protocol", q.protocol());
            qj.put("latencyMs", durationMs(q.latency()));
            if (q.tcpFallback()) qj.put("tcpFallback", true);
            if (q.nsid() != null) qj.put("nsid", q.nsid());
            if (q.error() != null) qj.put("error", q.error());
            list.add(qj);
        }
        return list;
    }

    private Map<String, Object> buildStatsJson(TraceModel.LevelStats stats) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("totalQueries", stats.totalQueries());
        s.put("udpQueries", stats.udpQueries());
        s.put("tcpQueries", stats.tcpQueries());
        s.put("tcpFallbacks", stats.tcpFallbacks());
        s.put("failedQueries", stats.failedQueries());
        s.put("minLatencyMs", durationMs(stats.minLatency()));
        s.put("maxLatencyMs", durationMs(stats.maxLatency()));
        return s;
    }

    private List<Map<String, Object>> buildVariantsJson(Map<Set<String>, List<String>> variants) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (var entry : variants.entrySet()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("nsSet", new ArrayList<>(entry.getKey()));
            v.put("servers", entry.getValue());
            list.add(v);
        }
        return list;
    }

    private double durationMs(Duration d) {
        if (d == null) return 0;
        return Math.round(d.toNanos() / 1_000_000.0 * 100.0) / 100.0;
    }
}
