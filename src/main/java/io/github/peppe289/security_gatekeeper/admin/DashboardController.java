package io.github.peppe289.security_gatekeeper.admin;

import static io.github.peppe289.security_gatekeeper.gateway.ProxyEntryFilter.ADMIN_PATH;

import io.github.peppe289.security_gatekeeper.config.GatewayProperties;
import io.github.peppe289.security_gatekeeper.monitoring.LoadMonitor;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.InvalidRouteException;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.RouteAlreadyExistsException;
import io.github.peppe289.security_gatekeeper.route.RouteExceptions.RouteNotFoundException;
import io.github.peppe289.security_gatekeeper.route.RouteService;
import io.github.peppe289.security_gatekeeper.route.RouteService.CreatedRoute;
import jakarta.validation.Valid;
import java.security.Principal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Server-rendered admin dashboard. Every state change is a POST protected by
 * a CSRF token and follows Post/Redirect/Get; no data is refreshed in the
 * background.
 */
@Controller
@RequestMapping(ADMIN_PATH)
public class DashboardController {

    static final String REDIRECT_HOME = "redirect:" + ADMIN_PATH + "/";
    private static final String FLASH_SUCCESS = "success";
    private static final String FLASH_ERROR = "error";

    private final RouteService routes;
    private final DashboardService dashboard;
    private final LoadMonitor loadMonitor;
    private final String apiKeyHeader;
    private final String nodeId;
    private final long statsRefreshSeconds;
    private final long verifyCooldownSeconds;
    private final boolean persistentAnchors;

    public DashboardController(RouteService routes, DashboardService dashboard, LoadMonitor loadMonitor,
                               GatewayProperties properties) {
        this.routes = routes;
        this.dashboard = dashboard;
        this.loadMonitor = loadMonitor;
        this.apiKeyHeader = properties.apiKeyHeader();
        this.nodeId = properties.nodeId();
        this.statsRefreshSeconds = properties.dashboard().statsRefresh().toSeconds();
        this.verifyCooldownSeconds = properties.dashboard().verifyCooldown().toSeconds();
        this.persistentAnchors = properties.audit().persistentAnchors();
    }

    @GetMapping
    public String root() {
        return REDIRECT_HOME;
    }

    @GetMapping("/")
    public String home(Model model, Principal principal) {
        model.addAttribute("username", principal.getName());
        model.addAttribute("nodeId", nodeId);
        model.addAttribute("routes", routes.findAll());
        model.addAttribute("snapshot", dashboard.snapshot());
        model.addAttribute("load", loadMonitor.report());
        model.addAttribute("integrity", dashboard.lastIntegrity());
        model.addAttribute("apiKeyHeader", apiKeyHeader);
        model.addAttribute("statsRefreshSeconds", statsRefreshSeconds);
        model.addAttribute("verifyCooldownSeconds", verifyCooldownSeconds);
        model.addAttribute("persistentAnchors", persistentAnchors);
        if (!model.containsAttribute("routeForm")) {
            model.addAttribute("routeForm", RouteForm.withDefaults());
        }
        return "dashboard";
    }

    @PostMapping("/routes")
    public String createRoute(@Valid @ModelAttribute("routeForm") RouteForm form, BindingResult binding,
                              RedirectAttributes redirect) {
        if (binding.hasErrors()) {
            redirect.addFlashAttribute(FLASH_ERROR, binding.getAllErrors().get(0).getDefaultMessage());
            redirect.addFlashAttribute("routeForm", form);
            return REDIRECT_HOME;
        }
        try {
            CreatedRoute created = routes.create(form.toDefinition());
            redirect.addFlashAttribute(FLASH_SUCCESS, "Route /" + created.policy().getPrefix() + " created.");
            if (created.apiKey() != null) {
                redirect.addFlashAttribute("newApiKey", created.apiKey());
                redirect.addFlashAttribute("newApiKeyRoute", created.policy().getPrefix());
            }
        } catch (RouteAlreadyExistsException | InvalidRouteException e) {
            redirect.addFlashAttribute(FLASH_ERROR, e.getMessage());
            redirect.addFlashAttribute("routeForm", form);
        }
        return REDIRECT_HOME;
    }

    @PostMapping("/routes/{prefix}/enabled")
    public String setEnabled(@PathVariable String prefix, @RequestParam boolean enabled, RedirectAttributes redirect) {
        routes.setEnabled(prefix, enabled);
        redirect.addFlashAttribute(FLASH_SUCCESS, "Route /" + prefix + (enabled ? " enabled." : " disabled."));
        return REDIRECT_HOME;
    }

    @PostMapping("/routes/{prefix}/api-key")
    public String rotateApiKey(@PathVariable String prefix, RedirectAttributes redirect) {
        String key = routes.rotateApiKey(prefix);
        redirect.addFlashAttribute("newApiKey", key);
        redirect.addFlashAttribute("newApiKeyRoute", prefix);
        return REDIRECT_HOME;
    }

    @PostMapping("/routes/{prefix}/api-key/delete")
    public String removeApiKey(@PathVariable String prefix, RedirectAttributes redirect) {
        routes.removeApiKey(prefix);
        redirect.addFlashAttribute(FLASH_SUCCESS, "Route /" + prefix + " is now public (API key removed).");
        return REDIRECT_HOME;
    }

    @PostMapping("/routes/{prefix}/delete")
    public String deleteRoute(@PathVariable String prefix, RedirectAttributes redirect) {
        routes.delete(prefix);
        redirect.addFlashAttribute(FLASH_SUCCESS, "Route /" + prefix + " deleted.");
        return REDIRECT_HOME;
    }

    @PostMapping("/audit/verify")
    public String verifyAudit(RedirectAttributes redirect) {
        DashboardService.VerifyResult result = dashboard.verify();
        if (!result.fresh()) {
            redirect.addFlashAttribute(FLASH_ERROR, "Verification ran recently: try again in "
                    + Math.max(1, result.retryIn().toSeconds()) + " s.");
        } else if (result.report().valid()) {
            redirect.addFlashAttribute(FLASH_SUCCESS, "Audit chain intact: " + result.report().checkedRecords()
                    + " records and " + result.report().anchors() + " anchors verified.");
        } else if (result.report().brokenNode() == null) {
            redirect.addFlashAttribute(FLASH_ERROR, "Audit verification failed: " + result.report().problem() + ".");
        } else {
            redirect.addFlashAttribute(FLASH_ERROR, "Audit chain TAMPERED: node " + result.report().brokenNode()
                    + ", record #" + result.report().firstInvalidSequence() + " (" + result.report().problem() + ").");
        }
        return REDIRECT_HOME;
    }

    @ExceptionHandler(RouteNotFoundException.class)
    public String routeNotFound(RedirectAttributes redirect) {
        redirect.addFlashAttribute(FLASH_ERROR, "Route not found (it may have been deleted).");
        return REDIRECT_HOME;
    }
}
