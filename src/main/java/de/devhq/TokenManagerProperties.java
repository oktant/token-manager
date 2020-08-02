package de.devhq;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class TokenManagerProperties {
    private static String userId;
    private static String machineRole;
    private static String adminRole;
    private static String userRole;
    private static String keycloakUrl;
    private static SecurityContext securityContext;
    private static RestTemplate restTemplate;

    private TokenManagerProperties() {
    }

    public static String getUserId() {
        return userId;
    }

    public static String getMachineRole() {
        return machineRole;
    }

    public static String getAdminRole() {
        return adminRole;
    }

    public static String getUserRole() {
        return userRole;
    }

    public static String getKeycloakUrl() {
        return keycloakUrl;
    }

    public static SecurityContext getSecurityContext() {
        return securityContext;
    }

    public static RestTemplate getRestTemplate() {
        return restTemplate;
    }

    public static void setUp() throws IOException {
        Properties prop = readPropertiesFile();
        machineRole = getParameter(prop.getProperty("de.devhq.role.machine"));
        adminRole = getParameter(prop.getProperty("de.devhq.role.admin"));
        userRole = getParameter(prop.getProperty("de.devhq.role.user"));
        userId = getParameter(prop.getProperty("de.devhq.user.id"));
        keycloakUrl = getParameter(prop.getProperty("de.devhq.keycloak.url"));
        restTemplate = new RestTemplate();
    }

    private static String getParameter(String property){
        if(property.startsWith("${")){
           String secondSide=property.split(":", 2)[1];
            return secondSide.substring(0,secondSide.length()-1);
        }
        return property;
    }

    public static void setSecurityContext() {
        securityContext = SecurityContextHolder.getContext();
    }

    private static Properties readPropertiesFile() throws IOException {
        InputStream fis = null;
        java.util.Properties prop = null;
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            fis = loader.getResourceAsStream("application.properties");
            prop = new java.util.Properties();
            prop.load(fis);
        } catch (IOException fnfe) {
            fnfe.printStackTrace();
        } finally {
            assert fis != null;
            fis.close();
        }
        return prop;
    }
}
