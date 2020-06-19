package de.devhq;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class TokenManagerProperties {
    public static String USERID;
    public static String MACHINEROLE;
    public static String ADMINROLE;
    public static String USERROLE;
    public static String KEYCLOAKURL;
    public static SecurityContext SECURITYCONTEXT;
    public static RestTemplate RESTTEMPLATE;

    public static void setUp() throws IOException {
        Properties prop = readPropertiesFile("application.properties");
        MACHINEROLE=prop.getProperty("de.devhq.role.machine");
        ADMINROLE=prop.getProperty("de.devhq.role.admin");
        USERROLE=prop.getProperty("de.devhq.role.user");
        USERID = prop.getProperty("de.devhq.user.id");
        KEYCLOAKURL = prop.getProperty("de.devhq.keycloak.url");
        SECURITYCONTEXT = SecurityContextHolder.getContext();
        RESTTEMPLATE = new RestTemplate();
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
