package io.github.peppe289.security_gatekeeper.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/** The admin password is required: the gateway must not start (and generate one) without it. */
class GatewayPropertiesTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = "   ")
    void missingAdminPasswordIsInvalid(String password) {
        Set<ConstraintViolation<GatewayProperties.Admin>> violations =
                validator.validate(new GatewayProperties.Admin("admin", password));

        assertEquals(1, violations.size());
        assertEquals("password", violations.iterator().next().getPropertyPath().toString());
    }

    @Test
    void plainOrEncodedPasswordIsValid() {
        assertTrue(validator.validate(new GatewayProperties.Admin("admin", "s3cret")).isEmpty());
        assertTrue(validator.validate(new GatewayProperties.Admin("admin", "{bcrypt}$2a$10$abc")).isEmpty());
    }

    @Test
    void toStringNeverShowsThePassword() {
        assertEquals("Admin[username=admin]", new GatewayProperties.Admin("admin", "s3cret").toString());
    }
}
