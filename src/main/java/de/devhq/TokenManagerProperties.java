package de.devhq;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class TokenManagerProperties {
    public static String userId;
    public static String machineRole;
    public static String adminRole;
    public static String userRole;
    public static String keycloakUrl;
    public static SecurityContext securityContext;
    public static RestTemplate restTemplate;

    public static void setUp() throws IOException {
        Properties prop = readPropertiesFile();
        machineRole=prop.getProperty("de.devhq.role.machine");
        adminRole=prop.getProperty("de.devhq.role.admin");
        userRole=prop.getProperty("de.devhq.role.user");
        userId = prop.getProperty("de.devhq.user.id");
        keycloakUrl = prop.getProperty("de.devhq.keycloak.url");
        securityContext = SecurityContextHolder.getContext();
        restTemplate = new RestTemplate();
    }
    private TokenManagerProperties(){
    }

    private static Properties readPropertiesFile() throws IOException {
        InputStream fis = null;
        java.util.Properties prop = null;
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            fis = loader.getResourceAsStream("application.properties");
            prop = new java.util.Properties();
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
