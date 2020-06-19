package de.devhq;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class TokenManagerProperties {
    public static String USER_ID;
    public static String MACHINE_ROLE;
    public static String ADMIN_ROLE;
    public static String USER_ROLE;
    public static String KEYCLOAK_URL;
    public static SecurityContext SECURITY_CONTEXT;
    public static RestTemplate REST_TEMPLATE;

    public static void setUp() throws IOException {
        Properties prop = readPropertiesFile("application.properties");
        MACHINE_ROLE=prop.getProperty("de.devhq.role.machine");
        ADMIN_ROLE=prop.getProperty("de.devhq.role.admin");
        USER_ROLE=prop.getProperty("de.devhq.role.user");
        USER_ID = prop.getProperty("de.devhq.user.id");
        KEYCLOAK_URL = prop.getProperty("de.devhq.keycloak.url");
        SECURITY_CONTEXT = SecurityContextHolder.getContext();
        REST_TEMPLATE = new RestTemplate();
    }
    private TokenManagerProperties(){
    }

    public static java.util.Properties readPropertiesFile(String fileName) throws IOException {
        InputStream fis = null;
        java.util.Properties prop = null;
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            fis = loader.getResourceAsStream(fileName);
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
