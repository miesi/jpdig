package de.mieslinger.jpdig;

import org.xbill.DNS.DClass;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.GenericEDNSOption;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * DNS query client wrapping dnsjava with latency measurement,
 * NSID support, and automatic TCP fallback.
 */
public class DnsClient {

    private static final int NSID_OPTION_CODE = 3;

    private final int timeoutMs;
    private final int retries;
    private final boolean forceTcp;
    private final boolean requestNsid;

    public DnsClient(int timeoutMs, int retries, boolean forceTcp, boolean requestNsid) {
        this.timeoutMs = timeoutMs;
        this.retries = retries;
        this.forceTcp = forceTcp;
        this.requestNsid = requestNsid;
    }

    /**
     * Send a DNS query to a specific server and measure latency.
     */
    public TraceModel.QueryResult query(InetAddress server, String serverName, Name name, int type) {
        long startNs = System.nanoTime();
        String protocol = forceTcp ? "TCP" : "UDP";
        boolean tcpFallback = false;
        String nsid = null;
        Message response = null;
        String error = null;

        try {
            SimpleResolver resolver = createResolver(server);
            Message queryMsg = createQuery(name, type);

            response = sendWithRetries(resolver, queryMsg);

            // Check for truncation -> TCP fallback
            if (response != null && !forceTcp && response.getHeader().getFlag(Flags.TC)) {
                tcpFallback = true;
                protocol = "TCP(fallback)";
                resolver.setTCP(true);
                response = sendWithRetries(resolver, queryMsg);
            }

            // Extract NSID from response
            if (requestNsid && response != null) {
                nsid = extractNsid(response);
            }
        } catch (Exception e) {
            error = e.getClass().getSimpleName() + ": " + e.getMessage();
        }

        long elapsedNs = System.nanoTime() - startNs;
        Duration latency = Duration.ofNanos(elapsedNs);

        return new TraceModel.QueryResult(server, serverName, response, latency, protocol, tcpFallback, nsid, error);
    }

    private SimpleResolver createResolver(InetAddress server) throws IOException {
        SimpleResolver resolver = new SimpleResolver(new InetSocketAddress(server, 53));
        resolver.setTimeout(Duration.ofMillis(timeoutMs));
        resolver.setTCP(forceTcp);
        return resolver;
    }

    private Message createQuery(Name name, int type) throws IOException {
        org.xbill.DNS.Record question = org.xbill.DNS.Record.newRecord(name, type, DClass.IN);
        Message query = Message.newQuery(question);

        // Disable recursion desired
        query.getHeader().unsetFlag(Flags.RD);

        // Add EDNS OPT record
        if (requestNsid) {
            List<EDNSOption> options = new ArrayList<>();
            options.add(new GenericEDNSOption(NSID_OPTION_CODE, new byte[0]));
            OPTRecord opt = new OPTRecord(4096, 0, 0, 0, options);
            query.addRecord(opt, Section.ADDITIONAL);
        } else {
            OPTRecord opt = new OPTRecord(4096, 0, 0);
            query.addRecord(opt, Section.ADDITIONAL);
        }

        return query;
    }

    private Message sendWithRetries(SimpleResolver resolver, Message query) throws IOException {
        IOException lastException = null;
        for (int attempt = 0; attempt <= retries; attempt++) {
            try {
                return resolver.send(query);
            } catch (IOException e) {
                lastException = e;
                if (attempt < retries) {
                    try {
                        Thread.sleep(100L * (attempt + 1));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw e;
                    }
                }
            }
        }
        throw lastException;
    }

    /**
     * Extract NSID from the response OPT record.
     * dnsjava's EDNSOption.toString() returns format like {NSID: <hexstring>}.
     * We decode the hex to get the actual NSID text.
     */
    private String extractNsid(Message response) {
        OPTRecord opt = response.getOPT();
        if (opt == null) return null;

        for (EDNSOption option : opt.getOptions()) {
            if (option.getCode() == NSID_OPTION_CODE) {
                String repr = option.toString();
                if (repr == null || repr.isEmpty()) continue;

                // Parse hex from format: {NSID: <hexstring>}
                int start = repr.indexOf('<');
                int end = repr.indexOf('>');
                if (start >= 0 && end > start) {
                    String hex = repr.substring(start + 1, end);
                    return hexToAscii(hex);
                }
                return repr.strip();
            }
        }
        return null;
    }

    private static String hexToAscii(String hex) {
        if (hex.length() % 2 != 0) return hex;
        StringBuilder sb = new StringBuilder();
        boolean allPrintable = true;
        for (int i = 0; i < hex.length(); i += 2) {
            int val = Integer.parseInt(hex.substring(i, i + 2), 16);
            if (val < 0x20 || val > 0x7E) {
                allPrintable = false;
                break;
            }
            sb.append((char) val);
        }
        return allPrintable ? sb.toString() : "0x" + hex.toLowerCase();
    }
}
