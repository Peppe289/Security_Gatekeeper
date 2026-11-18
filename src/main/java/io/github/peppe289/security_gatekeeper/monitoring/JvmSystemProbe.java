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
 *   <li>CPU and memory come from the platform {@code OperatingSystemMXBean}, which is
 *       container-aware: inside Docker it reports the container's usage against its
 *       limits (cgroups), not the host's.</li>
 *   <li>Network traffic comes from {@code /proc/net/dev}. A container has its own
 *       network namespace, so these are the container's interfaces. Outside Linux the
 *       file does not exist and the traffic is reported as unavailable.</li>
 * </ul>
 */
@Component
public class JvmSystemProbe implements SystemProbe {

    private static final Path PROC_NET_DEV = Path.of("/proc/net/dev");
    // Fields of /proc/net/dev after "iface:": receive bytes is the 1st, transmit bytes the 9th.
    private static final int RX_BYTES = 0;
    private static final int TX_BYTES = 8;

    private final com.sun.management.OperatingSystemMXBean os;
    private final MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
    private final Path netDev;

    public JvmSystemProbe() {
        this(PROC_NET_DEV);
    }

    JvmSystemProbe(Path netDev) {
        this.os = ManagementFactory.getPlatformMXBean(com.sun.management.OperatingSystemMXBean.class);
        this.netDev = netDev;
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
        MemoryUsage heap = memory.getHeapMemoryUsage();
        long[] net = readNetwork();
        return new Reading(cpu, Runtime.getRuntime().availableProcessors(), memoryUsed, memoryTotal, heap.getUsed(),
                heap.getMax(), net[0], net[1]);
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
