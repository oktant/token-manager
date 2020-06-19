package de.devhq.client.credentials;

import de.devhq.TokenManagerProperties;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.representations.AccessToken;

import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.test.util.ReflectionTestUtils;

import javax.servlet.http.HttpServletRequest;
import javax.validation.ValidationException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorTest {

    @Mock
    TokenManagerProperties tokenManagerProperties;
    SecurityContext securityContext;
    @Before
    public void setUp(){
        securityContext = Mockito.mock(SecurityContext.class);
        ReflectionTestUtils.setField(tokenManagerProperties, "USER_ID", "gitlab_user_id");
        ReflectionTestUtils.setField(tokenManagerProperties, "MACHINE_ROLE", "MACHINE_ROLE");
        ReflectionTestUtils.setField(tokenManagerProperties, "ADMIN_ROLE", "ADMIN_ROLE");
        ReflectionTestUtils.setField(tokenManagerProperties, "USER_ROLE", "USER_ROLE");
        ReflectionTestUtils.setField(tokenManagerProperties, "SECURITY_CONTEXT", securityContext);

    }

    @Test(expected = ValidationException.class)
    public void extractUserIdFromJwtWithNullClaims() {
        AbstractAuthenticationToken authentication = Mockito.mock(AbstractAuthenticationToken.class);
        SimpleKeycloakAccount simpleKeycloakAccount = mock(SimpleKeycloakAccount.class);
        AccessToken accessToken=mock(AccessToken.class);
        RefreshableKeycloakSecurityContext refreshableKeycloakSecurityContext=mock(RefreshableKeycloakSecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getDetails()).thenReturn(simpleKeycloakAccount);
        when(simpleKeycloakAccount.getKeycloakSecurityContext()).thenReturn(refreshableKeycloakSecurityContext);
        when(refreshableKeycloakSecurityContext.getToken()).thenReturn(accessToken);
        JwtValidator.extractUserIdFromJwt();
    }

    @Test
    public void extractUserIdFromJwt() {
        AbstractAuthenticationToken authentication = Mockito.mock(AbstractAuthenticationToken.class);
        SimpleKeycloakAccount simpleKeycloakAccount = mock(SimpleKeycloakAccount.class);
        AccessToken accessToken=new AccessToken();
        accessToken.setOtherClaims("gitlab_user_id", "1");
        RefreshableKeycloakSecurityContext refreshableKeycloakSecurityContext=mock(RefreshableKeycloakSecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getDetails()).thenReturn(simpleKeycloakAccount);
        when(simpleKeycloakAccount.getKeycloakSecurityContext()).thenReturn(refreshableKeycloakSecurityContext);
        when(refreshableKeycloakSecurityContext.getToken()).thenReturn(accessToken);
        assertEquals(1, JwtValidator.extractUserIdFromJwt());
    }

    @Test(expected = ValidationException.class)
    public void extractUserIdFromJwtWith0() {
        AbstractAuthenticationToken authentication = Mockito.mock(AbstractAuthenticationToken.class);
        SimpleKeycloakAccount simpleKeycloakAccount = mock(SimpleKeycloakAccount.class);
        AccessToken accessToken=new AccessToken();
        accessToken.setOtherClaims("gitlab_user_id", "0");
        RefreshableKeycloakSecurityContext refreshableKeycloakSecurityContext=mock(RefreshableKeycloakSecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        when(authentication.getDetails()).thenReturn(simpleKeycloakAccount);
        when(simpleKeycloakAccount.getKeycloakSecurityContext()).thenReturn(refreshableKeycloakSecurityContext);
        when(refreshableKeycloakSecurityContext.getToken()).thenReturn(accessToken);
        JwtValidator.extractUserIdFromJwt();
    }


    @Test
    public void isInternalUser() {
        HttpServletRequest httpServletRequest=mock(HttpServletRequest.class);
        assertFalse(JwtValidator.isInternalUser(httpServletRequest));

    }

    @Test
    public void isInternalUserMachineRole() {
        HttpServletRequest httpServletRequest=mock(HttpServletRequest.class);
        when(httpServletRequest.isUserInRole("MACHINE_ROLE")).thenReturn(true);
        assertTrue(JwtValidator.isInternalUser(httpServletRequest));

    }
    @Test
    public void isInternalUserMAdminRole() {
        HttpServletRequest httpServletRequest=mock(HttpServletRequest.class);
        when(httpServletRequest.isUserInRole("ADMIN_ROLE")).thenReturn(true);
        assertTrue(JwtValidator.isInternalUser(httpServletRequest));

    }

    @Test
    public void isExternalUser() {
        HttpServletRequest httpServletRequest=mock(HttpServletRequest.class);
        assertFalse(JwtValidator.isExternalUser(httpServletRequest));
    }

    @Test
    public void isExternalUserMachineRole() {
        HttpServletRequest httpServletRequest=mock(HttpServletRequest.class);
        when(httpServletRequest.isUserInRole("MACHINE_ROLE")).thenReturn(true);
        assertFalse(JwtValidator.isExternalUser(httpServletRequest));
    }

    @Test
    public void isExternalUserAdminRole() {
        HttpServletRequest httpServletRequest=mock(HttpServletRequest.class);
        when(httpServletRequest.isUserInRole("ADMIN_ROLE")).thenReturn(true);
        assertFalse(JwtValidator.isExternalUser(httpServletRequest));
    }

    @Test
    public void isExternalUserUserRole() {
        HttpServletRequest httpServletRequest=mock(HttpServletRequest.class);
        when(httpServletRequest.isUserInRole("USER_ROLE")).thenReturn(true);
        assertTrue(JwtValidator.isExternalUser(httpServletRequest));
    }
}