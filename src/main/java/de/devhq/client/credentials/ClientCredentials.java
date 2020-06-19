package de.devhq.client.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.devhq.TokenManagerProperties;
import de.devhq.model.TokenCollection;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.http.HttpHeaders;

import javax.security.sasl.AuthenticationException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;

import static java.util.Arrays.asList;

public class ClientCredentials {

    private ClientCredentials()  {
    }

    public static HttpHeaders getHttpHeaders(String clientId, String clientSecret){

        TokenCollection tokenCollection=new TokenCollection();
        HttpHeaders httpHeaders = new HttpHeaders();
        try{
            tokenCollection=getToken(clientId, clientSecret);
        } catch (IOException e) {
            e.printStackTrace();
        }
        httpHeaders.set("Authorization", tokenCollection.getAccessToken());
        return httpHeaders;
    }
    private static TokenCollection tokenCollection;

    public static TokenCollection getToken(String clientId, String clientSecret) throws IOException {
            HttpPost post = getPost(clientId, clientSecret);
            TokenCollection tokenCollectionCurrent = getTokenCollection(post);
            if (tokenCollectionCurrent == null || tokenCollectionCurrent.getAccessToken() == null) {
                throw new AuthenticationException();
            }
            return getTokenCollection(post);
    }

    private static TokenCollection getTokenCollection(HttpPost post) throws IOException {
        try (CloseableHttpClient httpclient = HttpClients.createDefault()) {
            return httpclient.execute(
                    post,
                    response -> {
                        ObjectMapper mapper = new ObjectMapper();
                        int status = response.getStatusLine().getStatusCode();

                        if (status >= 200 && status < 300) {
                            tokenCollection =
                                    mapper.readValue(response.getEntity().getContent(), TokenCollection.class);

                            return tokenCollection;

                        } else {
                            return null;
                        }
                    });
        }
    }

    private static HttpPost getPost(String clientId, String clientSecret) throws UnsupportedEncodingException {
        HttpPost post = new HttpPost(TokenManagerProperties.KEYCLOAK_URL);
        List<NameValuePair> params =
                asList(
                        new BasicNameValuePair("grant_type", "client_credentials"),
                        new BasicNameValuePair("client_id", clientId),
                        new BasicNameValuePair("client_secret", clientSecret));

        post.setEntity(new UrlEncodedFormEntity(params));
        post.addHeader("Content-Type", "application/x-www-form-urlencoded");
        return post;
    }
}
