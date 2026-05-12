package de.mieslinger.jpdig;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Cymru-style ASN lookup via TXT queries against origin.asn.cymru.com
 * (IPv4) and origin6.asn.cymru.com (IPv6).
 *
 * Response format from Cymru:
 *   "8560 | 185.132.32.0/22 | DE | ripencc | 2014-01-01"
 *
 * Lookups are performed via the system stub resolver (default
 * /etc/resolv.conf). Results are cached per-IP for the lifetime of
 * this instance (one trace run).
 */
public class IpInfoLookup {

    private final String provider4;
    private final String provider6;
    private final int timeoutMs;

    private final ConcurrentHashMap<InetAddress, TraceModel.IpInfo> cache =
            new ConcurrentHashMap<>();
    /** Sentinel for "lookup failed / no data" so we don't retry. */
    private static final TraceModel.IpInfo NONE =
            new TraceModel.IpInfo(null, null, null, null, null);

    public IpInfoLookup(String provider4, String provider6, int timeoutMs) {
        this.provider4 = stripTrailingDot(provider4);
        this.provider6 = stripTrailingDot(provider6);
        this.timeoutMs = timeoutMs;
    }

    /**
     * Look up info for a single IP, blocking. Returns null if no data.
     */
    public TraceModel.IpInfo lookup(InetAddress ip) {
        TraceModel.IpInfo cached = cache.get(ip);
        if (cached != null) {
            return cached == NONE ? null : cached;
        }
        TraceModel.IpInfo info = doLookup(ip);
        cache.put(ip, info == null ? NONE : info);
        return info;
    }

    /**
     * Look up info for many IPs in parallel via virtual threads.
     * Results are stored in the internal cache; subsequent lookup()
     * calls return them without further DNS queries.
     */
    public void prefetch(Collection<InetAddress> ips) {
        List<InetAddress> todo = new ArrayList<>();
        for (InetAddress ip : ips) {
            if (ip != null && !cache.containsKey(ip)) todo.add(ip);
        }
        if (todo.isEmpty()) return;

        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> futures = new ArrayList<>();
            for (InetAddress ip : todo) {
                futures.add(exec.submit(() -> lookup(ip)));
            }
            for (Future<?> f : futures) {
                try {
                    f.get();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private TraceModel.IpInfo doLookup(InetAddress ip) {
        String qname;
        if (ip instanceof Inet4Address) {
            qname = reverseV4(ip.getHostAddress()) + "." + provider4 + ".";
        } else if (ip instanceof Inet6Address) {
            qname = nibbleReverseV6((Inet6Address) ip) + "." + provider6 + ".";
        } else {
            return null;
        }

        try {
            Name name = Name.fromString(qname);
            Resolver resolver = defaultResolver();
            if (resolver == null) return null;
            resolver.setTimeout(Duration.ofMillis(timeoutMs));

            Lookup lookup = new Lookup(name, Type.TXT, DClass.IN);
            lookup.setResolver(resolver);
            lookup.setCache(null);
            Record[] records = lookup.run();
            if (records == null) return null;

            for (Record rec : records) {
                if (rec instanceof TXTRecord txt) {
                    String joined = String.join("", txt.getStrings());
                    TraceModel.IpInfo info = parse(joined);
                    if (info != null) return info;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Parse a Cymru-style pipe-separated TXT record into IpInfo.
     * Expected: "ASN | prefix | CC | RIR | YYYY-MM-DD"
     */
    static TraceModel.IpInfo parse(String txt) {
        if (txt == null || txt.isBlank()) return null;
        String[] parts = txt.split("\\|");
        for (int i = 0; i < parts.length; i++) parts[i] = parts[i].trim();

        String asn = parts.length > 0 && !parts[0].isEmpty() ? parts[0] : null;
        String prefix = parts.length > 1 && !parts[1].isEmpty() ? parts[1] : null;
        String country = parts.length > 2 && !parts[2].isEmpty()
                ? parts[2].toLowerCase() : null;
        String rir = parts.length > 3 && !parts[3].isEmpty()
                ? parts[3].toLowerCase() : null;
        String date = parts.length > 4 && !parts[4].isEmpty() ? parts[4] : null;

        if (asn == null && prefix == null && country == null
                && rir == null && date == null) {
            return null;
        }
        return new TraceModel.IpInfo(asn, prefix, country, rir, date);
    }

    private static String reverseV4(String addr) {
        String[] o = addr.split("\\.");
        StringBuilder sb = new StringBuilder();
        for (int i = o.length - 1; i >= 0; i--) {
            if (sb.length() > 0) sb.append('.');
            sb.append(o[i]);
        }
        return sb.toString();
    }

    private static String nibbleReverseV6(Inet6Address ip) {
        byte[] bytes = ip.getAddress();
        StringBuilder sb = new StringBuilder(64);
        for (int i = bytes.length - 1; i >= 0; i--) {
            int b = bytes[i] & 0xFF;
            int low = b & 0x0F;
            int high = (b >> 4) & 0x0F;
            sb.append(Integer.toHexString(low)).append('.');
            sb.append(Integer.toHexString(high));
            if (i > 0) sb.append('.');
        }
        return sb.toString();
    }

    private static Resolver defaultResolver() {
        try {
            return new SimpleResolver();
        } catch (Exception e) {
            return null;
        }
    }

    private static String stripTrailingDot(String s) {
        if (s == null) return null;
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }
}
