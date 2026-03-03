package de.mieslinger.jpdig;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Hardcoded root server hints (names and addresses).
 * Based on the IANA root hints file.
 */
public final class RootHints {

    private RootHints() {}

    public record RootServer(String name, List<InetAddress> v4, List<InetAddress> v6) {
        public List<InetAddress> allAddresses() {
            var all = new ArrayList<InetAddress>();
            all.addAll(v4);
            all.addAll(v6);
            return all;
        }
    }

    private static final List<RootServer> ROOT_SERVERS;

    static {
        try {
            ROOT_SERVERS = List.of(
                root("a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"),
                root("b.root-servers.net.", "170.247.170.2", "2801:1b8:10::b"),
                root("c.root-servers.net.", "192.33.4.12", "2001:500:2::c"),
                root("d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"),
                root("e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"),
                root("f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"),
                root("g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"),
                root("h.root-servers.net.", "198.97.190.53", "2001:500:1::53"),
                root("i.root-servers.net.", "192.36.148.17", "2001:7fe::53"),
                root("j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"),
                root("k.root-servers.net.", "193.0.14.129", "2001:7fd::1"),
                root("l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"),
                root("m.root-servers.net.", "202.12.27.33", "2001:dc3::35")
            );
        } catch (UnknownHostException e) {
            throw new RuntimeException("Failed to initialize root hints", e);
        }
    }

    private static RootServer root(String name, String v4, String v6) throws UnknownHostException {
        return new RootServer(
                name,
                List.of(InetAddress.getByName(v4)),
                List.of(InetAddress.getByName(v6))
        );
    }

    public static List<RootServer> getAll() {
        return ROOT_SERVERS;
    }

    /** Get all root server IPs filtered by connectivity. */
    public static List<InetAddress> getAllAddresses(boolean useV4, boolean useV6) {
        var addresses = new ArrayList<InetAddress>();
        for (var rs : ROOT_SERVERS) {
            if (useV4) addresses.addAll(rs.v4());
            if (useV6) addresses.addAll(rs.v6());
        }
        return addresses;
    }

    /** Get a map from IP to server name for all root servers. */
    public static Map<InetAddress, String> getAddressToNameMap() {
        var map = new HashMap<InetAddress, String>();
        for (var rs : ROOT_SERVERS) {
            for (var addr : rs.allAddresses()) {
                map.put(addr, rs.name());
            }
        }
        return map;
    }
}
