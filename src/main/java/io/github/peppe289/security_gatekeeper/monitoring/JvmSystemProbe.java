package io.github.peppe289.security_gatekeeper.monitoring;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * {@link SystemProbe} built on the JDK and on {@code /proc}.
 *
 * <ul>
 *   <li>CPU comes from the platform {@code OperatingSystemMXBean}, which is container-aware:
 *       inside Docker it reports the container's usage against its limits (cgroups).</li>
 *   <li>Memory excludes the <em>reclaimable page cache</em>: Linux keeps file pages in RAM
 *       until something else needs it, so "total minus free" looks almost full on a healthy
 *       machine. In a container with a memory limit (cgroup v2) the figure is
 *       {@code memory.current - inactive_file} against {@code memory.max}, as in
 *       {@code docker stats} and Kubernetes' working set; otherwise it is
 *       {@code MemTotal - MemAvailable} from {@code /proc/meminfo}, the "available" column of
 *       {@code free}. Where neither file exists (non-Linux) the JDK figures are used.</li>
 *   <li>Network traffic comes from {@code /proc/net/dev}. A container has its own
 *       network namespace, so these are the container's interfaces. Outside Linux the
 *       file does not exist and the traffic is reported as unavailable.</li>
 * </ul>
 */
@Component
public class JvmSystemProbe implements SystemProbe {

    private static final Path PROC_NET_DEV = Path.of("/proc/net/dev");
    private static final Path PROC_MEMINFO = Path.of("/proc/meminfo");
    private static final Path CGROUP = Path.of("/sys/fs/cgroup");
    private static final long KIB = 1024;
    // Fields of /proc/net/dev after "iface:": receive bytes is the 1st, transmit bytes the 9th.
    private static final int RX_BYTES = 0;
    private static final int TX_BYTES = 8;

    private final com.sun.management.OperatingSystemMXBean os;
    private final MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
    private final Path netDev;
    private final Path meminfo;
    private final Path cgroup;

    public JvmSystemProbe() {
        this(PROC_NET_DEV, PROC_MEMINFO, CGROUP);
    }

    JvmSystemProbe(Path netDev) {
        this(netDev, PROC_MEMINFO, CGROUP);
    }

    JvmSystemProbe(Path netDev, Path meminfo, Path cgroup) {
        this.os = ManagementFactory.getPlatformMXBean(com.sun.management.OperatingSystemMXBean.class);
        this.netDev = netDev;
        this.meminfo = meminfo;
        this.cgroup = cgroup;
    }

    @Override
    public Reading read() {
        double cpu = Double.NaN;
        long memoryUsed = -1;
        long memoryTotal = -1;
        if (os != null) {
            cpu = os.getCpuLoad();
            if (cpu < 0) {
                cpu = os.getProcessCpuLoad();
            }
            cpu = cpu < 0 ? Double.NaN : cpu;
            memoryTotal = os.getTotalMemorySize();
            memoryUsed = memoryTotal - os.getFreeMemorySize();
        }
        long[] mem = readMemory();
        if (mem != null) {
            memoryUsed = mem[0];
            memoryTotal = mem[1];
        }
        MemoryUsage heap = memory.getHeapMemoryUsage();
        long[] net = readNetwork();
        return new Reading(cpu, Runtime.getRuntime().availableProcessors(), memoryUsed, memoryTotal, heap.getUsed(),
                heap.getMax(), net[0], net[1]);
    }

    /** {@code {used, total}} without reclaimable cache, or {@code null} if not measurable here. */
    long[] readMemory() {
        try {
            long[] container = containerMemory(readFirstLine(cgroup.resolve("memory.max")),
                    readFirstLine(cgroup.resolve("memory.current")), readLines(cgroup.resolve("memory.stat")));
            return container != null ? container : hostMemory(readLines(meminfo));
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * cgroup v2 with a memory limit: usage minus the inactive file cache, against the limit.
     *
     * @return {@code null} without a numeric limit ({@code max}, or no cgroup files)
     */
    static long[] containerMemory(String max, String current, List<String> stat) {
        if (max == null || current == null || max.isBlank() || max.trim().equals("max")) {
            return null;
        }
        long limit = Long.parseLong(max.trim());
        long usage = Long.parseLong(current.trim());
        long inactiveFile = statValue(stat, "inactive_file");
        return new long[] {Math.max(0, usage - Math.max(0, inactiveFile)), limit};
    }

    /** {@code MemTotal - MemAvailable} from {@code /proc/meminfo}; {@code null} if either is missing. */
    static long[] hostMemory(List<String> meminfo) {
        long total = statValue(meminfo, "MemTotal:");
        long available = statValue(meminfo, "MemAvailable:");
        if (total <= 0 || available < 0) {
            return null;
        }
        return new long[] {Math.max(0, total - available) * KIB, total * KIB};
    }

    /** Value of the line starting with {@code key} (first number after it), or {@code -1}. */
    static long statValue(List<String> lines, String key) {
        if (lines == null) {
            return -1;
        }
        for (String line : lines) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length >= 2 && fields[0].equals(key)) {
                return Long.parseLong(fields[1]);
            }
        }
        return -1;
    }

    private static String readFirstLine(Path file) {
        List<String> lines = readLines(file);
        return lines == null || lines.isEmpty() ? null : lines.get(0);
    }

    private static List<String> readLines(Path file) {
        if (!Files.isReadable(file)) {
            return null;
        }
        try {
            return Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }

    private long[] readNetwork() {
        if (!Files.isReadable(netDev)) {
            return new long[] {-1, -1};
        }
        try {
            return parseNetDev(Files.readAllLines(netDev, StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            return new long[] {-1, -1};
        }
    }

    /** Sums received and sent bytes over every interface except loopback; {@code -1} if none is listed. */
    static long[] parseNetDev(List<String> lines) {
        long rx = 0;
        long tx = 0;
        boolean found = false;
        for (String line : lines) {
            int colon = line.indexOf(':');
            if (colon < 0) {
                continue; // header lines
            }
            if (line.substring(0, colon).trim().equals("lo")) {
                continue;
            }
            String[] fields = line.substring(colon + 1).trim().split("\\s+");
            if (fields.length <= TX_BYTES) {
                continue;
            }
            rx += Long.parseLong(fields[RX_BYTES]);
            tx += Long.parseLong(fields[TX_BYTES]);
            found = true;
        }
        return found ? new long[] {rx, tx} : new long[] {-1, -1};
    }
}
