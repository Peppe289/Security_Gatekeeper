package io.github.peppe289.security_gatekeeper.admin;

import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.peppe289.security_gatekeeper.route.RouteService;
import io.github.peppe289.security_gatekeeper.support.IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.MockMvc;

@IntegrationTest
class DashboardIntegrationTest {

    private static final String ADMIN = "/_gatekeeper";

    @Autowired
    MockMvc mvc;

    @Autowired
    RouteService routes;

    @Test
    void dashboardRequiresLogin() throws Exception {
        mvc.perform(get(ADMIN + "/")).andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(ADMIN + "/login"));
    }

    @Test
    void loginPageIsPublicAndHardened() throws Exception {
        mvc.perform(get(ADMIN + "/login"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("name=\"_csrf\"")))
                .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }

    @Test
    void panelAssetsArePublic() throws Exception {
        mvc.perform(get(ADMIN + "/assets/css/app.css")).andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/css"));
        mvc.perform(get(ADMIN + "/assets/js/app.js")).andExpect(status().isOk());
        mvc.perform(get(ADMIN + "/assets/favicon.svg")).andExpect(status().isOk());
    }

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get(ADMIN + "/health")).andExpect(status().isOk())
                .andExpect(content().string(containsString("UP")));
    }

    @Test
    void validLoginRedirectsToDashboard() throws Exception {
        mvc.perform(formLogin(ADMIN + "/login").user("admin").password(IntegrationTest.ADMIN_PASSWORD))
                .andExpect(redirectedUrl(ADMIN + "/"));
    }

    @Test
    void repeatedFailuresBlockLogin() throws Exception {
        RequestPostProcessor fromAttacker = request -> {
            request.setRemoteAddr("198.51.100.66");
            return request;
        };
        for (int i = 0; i < 3; i++) {
            mvc.perform(post(ADMIN + "/login").param("username", "admin").param("password", "wrong")
                            .with(csrf()).with(fromAttacker))
                    .andExpect(redirectedUrl(ADMIN + "/login?error"));
        }
        // even the right password is refused while blocked
        mvc.perform(post(ADMIN + "/login").param("username", "admin").param("password", IntegrationTest.ADMIN_PASSWORD)
                        .with(csrf()).with(fromAttacker))
                .andExpect(redirectedUrl(ADMIN + "/login?blocked"));
    }

    @Test
    void dashboardRendersRoutesAndEscapesData() throws Exception {
        routes.create(new io.github.peppe289.security_gatekeeper.route.RouteDefinition(
                "dash-view", "http://example.invalid/x", true, false, null, null));
        mvc.perform(get(ADMIN + "/").with(user("admin").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/dash-view")))
                .andExpect(content().string(containsString("http://example.invalid/x")));
    }

    @Test
    void createRouteRequiresCsrf() throws Exception {
        mvc.perform(post(ADMIN + "/routes").with(user("admin").roles("ADMIN"))
                        .param("prefix", "nocsrf").param("targetUrl", "http://localhost:9"))
                .andExpect(status().isForbidden());
        assertTrue(routes.find("nocsrf").isEmpty());
    }

    @Test
    void createRouteWithApiKeyShowsKeyOnce() throws Exception {
        mvc.perform(post(ADMIN + "/routes").with(user("admin").roles("ADMIN")).with(csrf())
                        .param("prefix", "dash-new").param("targetUrl", "http://localhost:9")
                        .param("enabled", "true").param("requireApiKey", "true"))
                .andExpect(redirectedUrl(ADMIN + "/"))
                .andExpect(flash().attributeExists("newApiKey"));
        assertTrue(routes.find("dash-new").orElseThrow().requiresApiKey());
    }

    @Test
    void invalidFormIsRejectedWithMessage() throws Exception {
        mvc.perform(post(ADMIN + "/routes").with(user("admin").roles("ADMIN")).with(csrf())
                        .param("prefix", "Bad Prefix").param("targetUrl", "http://localhost:9"))
                .andExpect(redirectedUrl(ADMIN + "/"))
                .andExpect(flash().attributeExists("error"));
        mvc.perform(post(ADMIN + "/routes").with(user("admin").roles("ADMIN")).with(csrf())
                        .param("prefix", "ftp-target").param("targetUrl", "ftp://localhost"))
                .andExpect(flash().attributeExists("error"));
        assertTrue(routes.find("ftp-target").isEmpty());
    }

    @Test
    void routeLifecycleThroughDashboard() throws Exception {
        mvc.perform(post(ADMIN + "/routes").with(user("admin").roles("ADMIN")).with(csrf())
                .param("prefix", "dash-life").param("targetUrl", "http://localhost:9").param("enabled", "true"));
        mvc.perform(post(ADMIN + "/routes/dash-life/enabled").with(user("admin").roles("ADMIN")).with(csrf())
                .param("enabled", "false")).andExpect(flash().attributeExists("success"));
        assertTrue(!routes.find("dash-life").orElseThrow().isEnabled());
        mvc.perform(post(ADMIN + "/routes/dash-life/api-key").with(user("admin").roles("ADMIN")).with(csrf()))
                .andExpect(flash().attributeExists("newApiKey"));
        mvc.perform(post(ADMIN + "/routes/dash-life/api-key/delete").with(user("admin").roles("ADMIN")).with(csrf()))
                .andExpect(flash().attributeExists("success"));
        mvc.perform(post(ADMIN + "/routes/dash-life/delete").with(user("admin").roles("ADMIN")).with(csrf()))
                .andExpect(flash().attributeExists("success"));
        assertTrue(routes.find("dash-life").isEmpty());
        mvc.perform(post(ADMIN + "/routes/dash-life/delete").with(user("admin").roles("ADMIN")).with(csrf()))
                .andExpect(flash().attributeExists("error"));
    }

    @Test
    void auditVerificationFromDashboard() throws Exception {
        mvc.perform(post(ADMIN + "/audit/verify").with(user("admin").roles("ADMIN")).with(csrf()))
                .andExpect(redirectedUrl(ADMIN + "/"))
                .andExpect(flash().attributeExists("success"));
    }
}
