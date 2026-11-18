package io.github.peppe289.security_gatekeeper.monitoring;

import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Component;

/**
 * Number of proxied requests being served right now. Each one holds a server
 * worker thread until the upstream has answered, so this is how close the
 * gateway is to running out of threads.
 */
@Component
public class InFlightRequests {

    private final AtomicInteger current = new AtomicInteger();
    private final AtomicInteger peak = new AtomicInteger();

    public void enter() {
        int now = current.incrementAndGet();
        peak.accumulateAndGet(now, Math::max);
    }

    public void exit() {
        current.decrementAndGet();
    }

    public int current() {
        return current.get();
    }

    /** @return the highest value since the previous call (short bursts between two samples are not missed) */
    int takePeak() {
        return peak.getAndSet(current.get());
    }
}
