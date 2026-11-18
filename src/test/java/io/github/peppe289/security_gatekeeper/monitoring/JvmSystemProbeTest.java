package io.github.peppe289.security_gatekeeper.monitoring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class JvmSystemProbeTest {

    private static final List<String> NET_DEV = List.of(
            "Inter-|   Receive                                                |  Transmit",
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed",
            "    lo:  999999     100    0    0    0     0          0         0   999999     100    0    0    0     0       0          0",
            "  eth0: 1000       10    0    0    0     0          0         0     2000      20    0    0    0     0       0          0",
            "  eth1:  500        5    0    0    0     0          0         0      700       7    0    0    0     0       0          0");

    @Test
    void sumsEveryInterfaceExceptLoopback() {
        assertArrayEquals(new long[] {1500, 2700}, JvmSystemProbe.parseNetDev(NET_DEV));
    }

    @Test
    void onlyLoopbackMeansUnavailable() {
        assertArrayEquals(new long[] {-1, -1}, JvmSystemProbe.parseNetDev(NET_DEV.subList(0, 3)));
    }

    @Test
    void readsNetworkFromTheGivenFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("dev");
        Files.write(file, NET_DEV);
        SystemProbe.Reading r = new JvmSystemProbe(file).read();
        assertEquals(1500, r.networkRxBytes());
        assertEquals(2700, r.networkTxBytes());
    }

    @Test
    void missingNetworkFileIsReportedAsUnavailable(@TempDir Path dir) {
        SystemProbe.Reading r = new JvmSystemProbe(dir.resolve("missing")).read();
        assertEquals(-1, r.networkRxBytes());
        assertEquals(-1, r.networkTxBytes());
        assertTrue(r.processors() >= 1);
        assertTrue(r.heapUsed() > 0);
    }
}
