package io.github.peppe289.security_gatekeeper.admin;

import io.github.peppe289.security_gatekeeper.core.routing.RoutePolicy;
import io.github.peppe289.security_gatekeeper.route.RouteDefinition;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Form backing object for "add route". A mutable bean so that unchecked
 * checkboxes naturally bind to {@code false}.
 */
public class RouteForm {

    @NotBlank(message = "Prefix is required")
    @Pattern(regexp = RoutePolicy.PREFIX_PATTERN,
            message = "Prefix: only a-z, 0-9 and '-', up to 63 characters, must not start with '-'")
    private String prefix;

    @NotBlank(message = "Target URL is required")
    @Size(max = 2048, message = "Target URL is too long")
    private String targetUrl;

    private boolean enabled;
    private boolean requireApiKey;

    @Min(value = 1, message = "Burst must be at least 1")
    @Max(value = RoutePolicy.MAX_BURST_CAPACITY, message = "Burst must be at most {value}")
    private Long burstCapacity;

    @Min(value = 1, message = "Requests/s must be at least 1")
    @Max(value = RoutePolicy.MAX_REFILL_PER_SECOND, message = "Requests/s must be at most {value}")
    private Long refillPerSecond;

    public static RouteForm withDefaults() {
        RouteForm form = new RouteForm();
        form.setEnabled(true);
        return form;
    }

    public RouteDefinition toDefinition() {
        return new RouteDefinition(prefix == null ? null : prefix.trim(), targetUrl == null ? null : targetUrl.trim(),
                enabled, requireApiKey, burstCapacity, refillPerSecond);
    }

    public String getPrefix() {
        return prefix;
    }

    public void setPrefix(String prefix) {
        this.prefix = prefix;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isRequireApiKey() {
        return requireApiKey;
    }

    public void setRequireApiKey(boolean requireApiKey) {
        this.requireApiKey = requireApiKey;
    }

    public Long getBurstCapacity() {
        return burstCapacity;
    }

    public void setBurstCapacity(Long burstCapacity) {
        this.burstCapacity = burstCapacity;
    }

    public Long getRefillPerSecond() {
        return refillPerSecond;
    }

    public void setRefillPerSecond(Long refillPerSecond) {
        this.refillPerSecond = refillPerSecond;
    }
}
