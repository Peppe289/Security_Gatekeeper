package io.github.peppe289.security_gatekeeper.monitoring;

import io.github.peppe289.security_gatekeeper.audit.AuditService;
import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Samples the load of this instance every {@code gateway.monitoring.sample-interval}
 * and keeps the samples of the last {@code gateway.monitoring.window}, so the
 * dashboard can show both the current value and the peak of each resource.
 *
 * <p>Sampling runs in the background whether or not anyone looks at the
 * dashboard, so peaks are recorded even when nobody is watching; rendering the
 * report only reads the samples.
 */
@Component
public class LoadMonitor {

    private final SystemProbe probe;
    private final InFlightRequests inFlight;
    private final LongSupplier totalRequests;
    private final IntSupplier auditQueued;
    private final int auditCapacity;
    private final int maxWorkers;
    private final Clock clock;
    private final Duration interval;
    private final Duration window;
    private final int maxSamples;

    private final Deque<Sample> samples = new ArrayDeque<>();
    private Counters previous;

    /**
     * One sample. Fractions are in {@code [0, 1]}; rates are per second; {@code NaN}
     * means "not measurable" (or, for rates, "no previous sample yet").
     */
    record Sample(Instant at, SystemProbe.Reading reading, int inFlightPeak, int auditQueued,
                  double rxBitsPerSecond, double txBitsPerSecond, double requestsPerSecond) {
    }

    private record Counters(Instant at, long rxBytes, long txBytes, long requests) {
    }

    @Autowired
    public LoadMonitor(SystemProbe probe, InFlightRequests inFlight, AuditService audit, Clock clock,
                       GatewayProperties properties, @Value("${server.tomcat.threads.max:200}") int maxWorkers) {
        this(probe, inFlight, () -> audit.stats().totalRequests(), () -> audit.stats().queued(),
                properties.audit().queueCapacity(), maxWorkers, clock, properties.monitoring().sampleInterval(),
                properties.monitoring().window());
    }

    LoadMonitor(SystemProbe probe, InFlightRequests inFlight, LongSupplier totalRequests, IntSupplier auditQueued,
                int auditCapacity, int maxWorkers, Clock clock, Duration interval, Duration window) {
        this.probe = probe;
        this.inFlight = inFlight;
        this.totalRequests = totalRequests;
        this.auditQueued = auditQueued;
        this.auditCapacity = auditCapacity;
        this.maxWorkers = maxWorkers;
        this.clock = clock;
        this.interval = interval;
        this.window = window;
        this.maxSamples = (int) Math.max(1, window.toMillis() / Math.max(1, interval.toMillis()));
    }

    public Duration interval() {
        return interval;
    }

    /** Takes one sample. Called every {@code sample-interval} by the scheduler. */
    public synchronized void sample() {
        Instant now = clock.instant();
        SystemProbe.Reading r = probe.read();
        Counters counters = new Counters(now, r.networkRxBytes(), r.networkTxBytes(), totalRequests.getAsLong());
        double rx = Double.NaN;
        double tx = Double.NaN;
        double requests = Double.NaN;
        if (previous != null) {
            double seconds = Duration.between(previous.at(), now).toMillis() / 1000.0;
            rx = perSecond(previous.rxBytes(), counters.rxBytes(), seconds) * 8;
            tx = perSecond(previous.txBytes(), counters.txBytes(), seconds) * 8;
            requests = perSecond(previous.requests(), counters.requests(), seconds);
        }
        previous = counters;
        samples.addLast(new Sample(now, r, inFlight.takePeak(), auditQueued.getAsInt(), rx, tx, requests));
        while (samples.size() > maxSamples) {
            samples.removeFirst();
        }
    }

    /** Builds the report from the samples currently in the window. */
    public LoadReport report() {
        List<Sample> copy;
        synchronized (this) {
            copy = List.copyOf(samples);
        }
        return LoadReport.from(copy, maxWorkers, auditCapacity, interval, window);
    }

    /** {@code NaN} if a counter is unavailable or went backwards (interface reset, restart). */
    private static double perSecond(long before, long after, double seconds) {
        if (before < 0 || after < 0 || after < before || seconds <= 0) {
            return Double.NaN;
        }
        return (after - before) / seconds;
    }
}
