package de.devhq.client.credentials;

import de.devhq.TokenManagerProperties;
import de.devhq.model.TokenCollection;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.security.sasl.AuthenticationException;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


@RunWith(MockitoJUnitRunner.class)
public class ClientCredentialsTest {
    @Mock
    TokenManagerProperties tokenManagerProperties;
    RestTemplate restTemplate;
    @Before
    public void setUp(){
        restTemplate=mock(RestTemplate.class);
        ReflectionTestUtils.setField(tokenManagerProperties, "USER_ID", "gitlab_user_id");
        ReflectionTestUtils.setField(tokenManagerProperties, "MACHINE_ROLE", "MACHINE_ROLE");
        ReflectionTestUtils.setField(tokenManagerProperties, "ADMIN_ROLE", "ADMIN_ROLE");
        ReflectionTestUtils.setField(tokenManagerProperties, "USER_ROLE", "USER_ROLE");
        ReflectionTestUtils.setField(tokenManagerProperties, "KEYCLOAK_URL", "dasd");
        ReflectionTestUtils.setField(tokenManagerProperties, "REST_TEMPLATE", restTemplate);

    }
    @Test(expected = AuthenticationException.class)
    public void getHttpHeadersWithOneLetterToken() throws IOException {
        TokenCollection tokenCollection=new TokenCollection();
        tokenCollection.setAccessToken("1");
        ResponseEntity<TokenCollection> tokenCollectionResponseEntity=new ResponseEntity<>(tokenCollection, HttpStatus.OK);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type","client_credentials");
        map.add("client_id","client_id");
        map.add("client_secret", "client_secret");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
        when(restTemplate.exchange(TokenManagerProperties.KEYCLOAK_URL, HttpMethod.POST, entity, TokenCollection.class)).thenReturn(tokenCollectionResponseEntity);

        assertEquals(tokenCollection.getAccessToken(),ClientCredentials.getHttpHeaders("client_id", "client_secret").get("Authorization").get(0));
    }

    @Test
    public void getHttpHeaders() throws IOException {
        TokenCollection tokenCollection=new TokenCollection();
        tokenCollection.setAccessToken("test_token");
        ResponseEntity<TokenCollection> tokenCollectionResponseEntity=new ResponseEntity<>(tokenCollection, HttpStatus.OK);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type","client_credentials");
        map.add("client_id","client_id");
        map.add("client_secret", "client_secret");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
        when(restTemplate.exchange(TokenManagerProperties.KEYCLOAK_URL, HttpMethod.POST, entity, TokenCollection.class)).thenReturn(tokenCollectionResponseEntity);

        assertEquals(tokenCollection.getAccessToken(),ClientCredentials.getHttpHeaders("client_id", "client_secret").get("Authorization").get(0));
    }

    @Test
    public void getToken() throws IOException {
        TokenCollection tokenCollection=new TokenCollection();
        tokenCollection.setAccessToken("test_token");
        ResponseEntity<TokenCollection> tokenCollectionResponseEntity=new ResponseEntity<>(tokenCollection, HttpStatus.OK);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type","client_credentials");
        map.add("client_id","client_id");
        map.add("client_secret", "client_secret");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
        when(restTemplate.exchange(TokenManagerProperties.KEYCLOAK_URL, HttpMethod.POST, entity, TokenCollection.class)).thenReturn(tokenCollectionResponseEntity);

        assertEquals(tokenCollection.getAccessToken(),ClientCredentials.getToken("client_id", "client_secret").getAccessToken());
    }

    @Test (expected = AuthenticationException.class)
    public void getTokenWithEmptyToken() throws IOException {
        TokenCollection tokenCollection=new TokenCollection();
        ResponseEntity<TokenCollection> tokenCollectionResponseEntity=new ResponseEntity<>(tokenCollection, HttpStatus.OK);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type","client_credentials");
        map.add("client_id","client_id");
        map.add("client_secret", "client_secret");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
        when(restTemplate.exchange(TokenManagerProperties.KEYCLOAK_URL, HttpMethod.POST, entity, TokenCollection.class)).thenReturn(tokenCollectionResponseEntity);
        ClientCredentials.getToken("client_id", "client_secret");
    }
    @Test (expected = AuthenticationException.class)
    public void getTokenWithNull() throws IOException {
        TokenCollection tokenCollection=null;
        ResponseEntity<TokenCollection> tokenCollectionResponseEntity=new ResponseEntity<>(tokenCollection, HttpStatus.OK);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type","client_credentials");
        map.add("client_id","client_id");
        map.add("client_secret", "client_secret");
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);
        when(restTemplate.exchange(TokenManagerProperties.KEYCLOAK_URL, HttpMethod.POST, entity, TokenCollection.class)).thenReturn(null);
        ClientCredentials.getToken("client_id", "client_secret");
    }
}