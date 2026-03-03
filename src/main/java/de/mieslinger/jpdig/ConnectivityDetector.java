package de.mieslinger.jpdig;

import java.net.*;
import java.time.Duration;

/**
 * Detects IPv4 and IPv6 connectivity by attempting UDP DNS queries
 * to known root server addresses.
 */
public final class ConnectivityDetector {

    private ConnectivityDetector() {}

    /**
     * Detect available IP connectivity by trying to open UDP sockets
     * to root server addresses.
     */
    public static TraceModel.ConnectivityInfo detect(int timeoutMs) {
        // Use at least 1000ms for connectivity detection to avoid false negatives
        int detectTimeout = Math.max(timeoutMs, 1000);
        boolean v4 = testConnectivity(
                RootHints.getAll().getFirst().v4().getFirst(),
                detectTimeout
        );
        boolean v6 = testConnectivity(
                RootHints.getAll().getFirst().v6().getFirst(),
                detectTimeout
        );
        return new TraceModel.ConnectivityInfo(v4, v6);
    }

    private static boolean testConnectivity(InetAddress address, int timeoutMs) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeoutMs);
            // Build a minimal DNS query for . NS (root NS query)
            byte[] query = buildMinimalNsQuery();
            DatagramPacket packet = new DatagramPacket(query, query.length, address, 53);
            socket.send(packet);

            byte[] buf = new byte[512];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            socket.receive(response);
            return response.getLength() > 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Build a minimal DNS query for . NS (type=2, class=1).
     * Hand-crafted to avoid dependency on dnsjava for connectivity check.
     */
    private static byte[] buildMinimalNsQuery() {
        byte[] query = new byte[17];
        // Transaction ID
        query[0] = 0x00; query[1] = 0x01;
        // Flags: standard query, RD=0
        query[2] = 0x00; query[3] = 0x00;
        // Questions: 1
        query[4] = 0x00; query[5] = 0x01;
        // Answer RRs: 0
        query[6] = 0x00; query[7] = 0x00;
        // Authority RRs: 0
        query[8] = 0x00; query[9] = 0x00;
        // Additional RRs: 0
        query[10] = 0x00; query[11] = 0x00;
        // QNAME: . (root, just a zero-length label)
        query[12] = 0x00;
        // QTYPE: NS (2)
        query[13] = 0x00; query[14] = 0x02;
        // QCLASS: IN (1)
        query[15] = 0x00; query[16] = 0x01;
        return query;
    }
}
