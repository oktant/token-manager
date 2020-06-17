package de.devhq.mainmetric.util;

import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class JwtValidator {
    private static String USER_ID;
    private static String MACHINE_ROLE;
    private static String ADMIN_ROLE;
    private static String USER_ROLE;

    public static Logger logger = LoggerFactory.getLogger(JwtValidator.class);

    public static Integer extractUserIdFromJwt() throws ValidationException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        AbstractAuthenticationToken authenticationToken = (AbstractAuthenticationToken) securityContext.getAuthentication();
        SimpleKeycloakAccount details = (SimpleKeycloakAccount) authenticationToken.getDetails();
        Object value = details.getKeycloakSecurityContext().getToken().getOtherClaims().get(USER_ID);

        if (value == null) {
            logger.error("Requesting client is not an end user, hence token does not contain gitlab user id!");
            throw new ValidationException();
        }

        Integer userId = 0;
        userId = Integer.valueOf((String) value);

        if (userId <= 0) {
            logger.error("User id may not be none positive number! API seems to be hacked! Please report this to admin");
            throw new ValidationException();
        }

        return userId;
    }

    public static boolean isInternalUser(HttpServletRequest request) {
        return request.isUserInRole(MACHINE_ROLE) || request.isUserInRole(ADMIN_ROLE);
    }

    public static boolean isExternalUser(HttpServletRequest request) {
        return !(request.isUserInRole(MACHINE_ROLE) || request.isUserInRole(ADMIN_ROLE))
                && request.isUserInRole(USER_ROLE);
    }
    public static void setUp() throws IOException {
        Properties prop = readPropertiesFile("application.properties");
        MACHINE_ROLE=prop.getProperty("de.devhq.role.machine");
        ADMIN_ROLE=prop.getProperty("de.devhq.role.admin");
        USER_ROLE=prop.getProperty("de.devhq.role.user");
        USER_ID = prop.getProperty("de.devhq.user.id");
    }

    public static Properties readPropertiesFile(String fileName) throws IOException {
        InputStream fis = null;
        Properties prop = null;
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            fis = loader.getResourceAsStream(fileName);
            prop = new Properties();
            prop.load(fis);
        } catch(IOException fnfe) {
            fnfe.printStackTrace();
        } finally {
            assert fis != null;
            fis.close();
        }
        return prop;
    }
}
