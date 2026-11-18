package io.github.peppe289.security_gatekeeper.config;

import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

/**
 * Gateway configuration, bound from {@code application.yml} and overridable
 * with environment variables (e.g. {@code GATEWAY_ADMIN_PASSWORD},
 * {@code GATEWAY_NODEID}). Every value has a safe default.
 */
@Validated
@ConfigurationProperties(prefix = "gateway")
public record GatewayProperties(
        /* Identifies this instance in the audit log: each node writes its own hash chain. */
        @DefaultValue("node-1") @NotBlank @Pattern(regexp = "[A-Za-z0-9._-]{1,64}") String nodeId,
        @DefaultValue("X-Api-Key") @NotBlank String apiKeyHeader,
        @DefaultValue @Valid Admin admin,
        @DefaultValue @Valid Forwarder forwarder,
        @DefaultValue @Valid Routes routes,
        @DefaultValue @Valid RateLimit rateLimit,
        @DefaultValue @Valid LoginThrottle loginThrottle,
        @DefaultValue @Valid Audit audit,
        @DefaultValue @Valid Dashboard dashboard) {

    /**
     * Single admin account. If {@code password} is empty a random one is
     * generated at startup and logged once. A value starting with {@code {id}}
     * (e.g. {@code {bcrypt}$2a$...}) is used as an already-encoded hash.
     */
    public record Admin(
            @DefaultValue("admin") @NotBlank String username,
            String password) {

        @Override
        public String toString() {
            return "Admin[username=" + username + "]";
        }
    }

    public record Forwarder(
            @DefaultValue("5s") @NotNull Duration connectTimeout,
            @DefaultValue("60s") @NotNull Duration responseTimeout) {
    }

    /**
     * @param refreshInterval how often the route cache is reloaded from the
     *                        database, so changes made on another instance propagate
     * @param seed            routes inserted at startup if their prefix does not exist yet
     */
    public record Routes(
            @DefaultValue("10s") @NotNull Duration refreshInterval,
            List<@Valid SeedRoute> seed) {

        public Routes {
            seed = seed == null ? List.of() : List.copyOf(seed);
        }
    }

    public record SeedRoute(
            @NotBlank String prefix,
            @NotBlank String targetUrl,
            @DefaultValue("true") boolean enabled,
            Long burstCapacity,
            Long refillPerSecond) {
    }

    public record RateLimit(
            @DefaultValue("100") @Min(1) @Max(RoutePolicy.MAX_BURST_CAPACITY) long defaultBurstCapacity,
            @DefaultValue("50") @Min(1) @Max(RoutePolicy.MAX_REFILL_PER_SECOND) long defaultRefillPerSecond,
            @DefaultValue("100000") @Min(1) int maxTrackedClients,
            @DefaultValue("60s") @NotNull Duration evictionInterval) {
    }

    /** Brute-force protection for the admin login: {@code maxFailures} burst, then one attempt every {@code recovery}. */
    public record LoginThrottle(
            @DefaultValue("5") @Min(1) long maxFailures,
            @DefaultValue("30s") @NotNull Duration recovery) {
    }

    /**
     * Audit events are queued in memory and written to the database in
     * batches by a background thread, so the request path never waits for I/O.
     *
     * @param queueCapacity    events buffered before new ones are dropped (and counted)
     * @param batchSize        maximum rows per INSERT batch
     * @param flushInterval    maximum time an event waits before being written
     * @param hmacKey          secret (at least 32 characters) used to authenticate every record
     *                         and anchor; required, and never stored in the database
     * @param previousHmacKeys retired keys, still accepted when verifying older records
     * @param anchorDir        directory, outside the database, where signed chain heads are
     *                         appended; if empty, anchors are only written to the log
     * @param anchorInterval   minimum time between two anchors of this node's chain
     */
    public record Audit(
            @DefaultValue("50000") @Min(1) int queueCapacity,
            @DefaultValue("500") @Min(1) @Max(10_000) int batchSize,
            @DefaultValue("500ms") @NotNull Duration flushInterval,
            @NotBlank @Size(min = 32) String hmacKey,
            List<@NotBlank @Size(min = 32) String> previousHmacKeys,
            String anchorDir,
            @DefaultValue("60s") @NotNull Duration anchorInterval) {

        public Audit {
            previousHmacKeys = previousHmacKeys == null ? List.of() : List.copyOf(previousHmacKeys);
            anchorDir = anchorDir == null || anchorDir.isBlank() ? null : anchorDir;
        }

        /** @return {@code true} if anchors are also written to {@link #anchorDir()} */
        public boolean persistentAnchors() {
            return anchorDir != null;
        }

        @Override
        public String toString() {
            // The keys are deliberately omitted.
            return "Audit[queueCapacity=" + queueCapacity + ", batchSize=" + batchSize + ", flushInterval="
                    + flushInterval + ", previousHmacKeys=" + previousHmacKeys.size() + ", anchorDir=" + anchorDir
                    + ", anchorInterval=" + anchorInterval + "]";
        }
    }

    /**
     * @param statsRefresh minimum interval between two recomputations of the
     *                     dashboard statistics (they are cached in between)
     * @param verifyCooldown minimum interval between two full audit verifications
     */
    public record Dashboard(
            @DefaultValue("5s") @NotNull Duration statsRefresh,
            @DefaultValue("30s") @NotNull Duration verifyCooldown,
            @DefaultValue("50") @Min(1) @Max(500) int recentAuditRows) {
    }
}
