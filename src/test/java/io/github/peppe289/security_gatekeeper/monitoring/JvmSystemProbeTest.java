package io.github.peppe289.security_gatekeeper.monitoring;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    // ---------------------------------------------------------------- memory without page cache

    /** A real /proc/meminfo: 38.6 GiB, 3.1 GiB free, but 23 GiB available (20 GiB of page cache). */
    private static final List<String> MEMINFO = List.of(
            "MemTotal:       40425732 kB",
            "MemFree:         3298868 kB",
            "MemAvailable:   24123384 kB",
            "Cached:         21533156 kB",
            "Dirty:              5736 kB");

    @Test
    void hostMemoryCountsAvailableMemoryAsFree() {
        long[] mem = JvmSystemProbe.hostMemory(MEMINFO);

        assertEquals((40425732L - 24123384L) * 1024, mem[0], "used = total - available");
        assertEquals(40425732L * 1024, mem[1]);
    }

    @Test
    void hostMemoryWithoutMemAvailableIsUnknown() {
        assertNull(JvmSystemProbe.hostMemory(MEMINFO.subList(0, 2)));
        assertNull(JvmSystemProbe.hostMemory(List.of()));
        assertNull(JvmSystemProbe.hostMemory(null));
    }

    @Test
    void containerMemoryExcludesTheInactiveFileCache() {
        List<String> stat = List.of("anon 100000000", "file 80000000", "active_file 30000000",
                "inactive_file 50000000");

        long[] mem = JvmSystemProbe.containerMemory("268435456", "180000000", stat);

        assertEquals(130_000_000L, mem[0], "usage - inactive_file");
        assertEquals(268_435_456L, mem[1], "the container limit");
    }

    @Test
    void containerMemoryNeverGoesNegativeAndToleratesAMissingStat() {
        assertEquals(0, JvmSystemProbe.containerMemory("1000", "10", List.of("inactive_file 50"))[0]);
        assertEquals(10, JvmSystemProbe.containerMemory("1000", "10", null)[0]);
    }

    @Test
    void containerWithoutALimitIsNotAContainerMeasure() {
        assertNull(JvmSystemProbe.containerMemory("max", "10", List.of()));
        assertNull(JvmSystemProbe.containerMemory(null, "10", List.of()));
        assertNull(JvmSystemProbe.containerMemory("1000", null, List.of()));
    }

    @Test
    void statValueMatchesWholeKeysOnly() {
        List<String> stat = List.of("active_file 1", "inactive_file 2");
        assertEquals(2, JvmSystemProbe.statValue(stat, "inactive_file"));
        assertEquals(1, JvmSystemProbe.statValue(stat, "active_file"));
        assertEquals(-1, JvmSystemProbe.statValue(stat, "file"));
    }

    @Test
    void limitedCgroupTakesPrecedenceOverMeminfo(@TempDir Path dir) throws Exception {
        Path cgroup = Files.createDirectory(dir.resolve("cgroup"));
        Files.writeString(cgroup.resolve("memory.max"), "1000\n");
        Files.writeString(cgroup.resolve("memory.current"), "600\n");
        Files.writeString(cgroup.resolve("memory.stat"), "inactive_file 200\n");
        Path meminfo = Files.write(dir.resolve("meminfo"), MEMINFO);

        SystemProbe.Reading r = new JvmSystemProbe(dir.resolve("net"), meminfo, cgroup).read();

        assertEquals(400, r.memoryUsed());
        assertEquals(1000, r.memoryTotal());
    }

    @Test
    void withoutACgroupLimitMeminfoIsUsed(@TempDir Path dir) throws Exception {
        Path cgroup = Files.createDirectory(dir.resolve("cgroup"));
        Files.writeString(cgroup.resolve("memory.max"), "max\n");
        Path meminfo = Files.write(dir.resolve("meminfo"), MEMINFO);

        SystemProbe.Reading r = new JvmSystemProbe(dir.resolve("net"), meminfo, cgroup).read();

        assertEquals((40425732L - 24123384L) * 1024, r.memoryUsed());
    }

    @Test
    void withNeitherSourceTheJdkFiguresAreKept(@TempDir Path dir) {
        JvmSystemProbe probe = new JvmSystemProbe(dir.resolve("net"), dir.resolve("none"), dir.resolve("none"));
        assertNull(probe.readMemory());
        SystemProbe.Reading r = probe.read();
        assertTrue(r.memoryTotal() > 0, "falls back to the OperatingSystemMXBean");
    }

    @Test
    void malformedFilesMeanUnknownNotACrash(@TempDir Path dir) throws Exception {
        Path cgroup = Files.createDirectory(dir.resolve("cgroup"));
        Files.writeString(cgroup.resolve("memory.max"), "not-a-number\n");
        Files.writeString(cgroup.resolve("memory.current"), "1\n");
        assertNull(new JvmSystemProbe(dir.resolve("net"), dir.resolve("none"), cgroup).readMemory());
    }
}
