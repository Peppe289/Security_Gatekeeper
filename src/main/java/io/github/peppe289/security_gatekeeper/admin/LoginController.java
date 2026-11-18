package io.github.peppe289.security_gatekeeper.admin;

import static io.github.peppe289.security_gatekeeper.admin.DashboardController.REDIRECT_HOME;
import static io.github.peppe289.security_gatekeeper.config.SecurityConfig.LOGIN_PATH;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping(LOGIN_PATH)
    public String login(Authentication authentication) {
        boolean loggedIn = authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof AnonymousAuthenticationToken);
        return loggedIn ? REDIRECT_HOME : "login";
    }
}
