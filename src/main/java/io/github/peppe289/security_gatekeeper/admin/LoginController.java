package io.github.peppe289.security_gatekeeper.admin;

import static io.github.peppe289.security_gatekeeper.gateway.ProxyEntryFilter.ADMIN_PATH;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping(ADMIN_PATH + "/login")
    public String login(Authentication authentication) {
        boolean loggedIn = authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
        return loggedIn ? "redirect:" + ADMIN_PATH + "/" : "login";
    }
}
