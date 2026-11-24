package io.github.peppe289.security_gatekeeper.monitoring;

/** Reads the resource usage of the machine (or container) the gateway runs on. */
public interface SystemProbe {

    Reading read();

    /**
     * One reading. Values that cannot be measured on this platform are {@code NaN}
     * (fractions) or {@code -1} (amounts).
     *
     * @param cpuLoad         CPU in use, as a fraction of the CPUs available to the container
     * @param processors      CPUs available to the container
     * @param memoryUsed      memory in use in the container, reclaimable page cache excluded, in bytes
     * @param memoryTotal     memory available to the container (its limit, or the host's memory)
     * @param heapUsed        JVM heap in use, in bytes
     * @param heapMax         maximum JVM heap, in bytes
     * @param networkRxBytes  bytes received on every non-loopback interface since boot
     * @param networkTxBytes  bytes sent on every non-loopback interface since boot
     */
    record Reading(double cpuLoad, int processors, long memoryUsed, long memoryTotal, long heapUsed, long heapMax,
                   long networkRxBytes, long networkTxBytes) {
    }
}
