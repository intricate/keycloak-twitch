package org.keycloak.social.twitch;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.resources.IdentityBrokerService;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Twitch identity provider.
 * <p>
 * For the most part, all of the methods defined in the class are
 * <i>exactly</i> the same as those in {@link OIDCIdentityProvider}. The only
 * difference is that, wherever a Twitch OAuth 2.0 access token response is
 * received, we convert it to a format that can be deserialized to an instance
 * of Keycloak's {@link AccessTokenResponse}.
 * <p>
 * Unfortunately, this conversion is necessary due to the fact that
 * <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth">
 * Twitch's authorization server implementation</a> diverges from the
 * <a href="https://tools.ietf.org/html/rfc6749">OAuth 2.0 specification</a>;
 * specifically, in their formatting of the "scope" parameter of the access
 * token response.
 * <p>
 * The <a href="https://tools.ietf.org/html/rfc6749#section-3.3">OAuth 2.0
 * specification</a> denotes that the scope parameter is to be expressed as "a
 * list of space-delimited, case-sensitive strings". However, in Twitch's
 * OAuth 2.0 Access Token response, the scope parameter is expressed as a JSON
 * array of strings.
 *
 * @see TwitchIdentityProvider#convertFromTwitchAccessTokenResponseToSpec(String)
 */
public class TwitchIdentityProvider extends OIDCIdentityProvider
    implements SocialIdentityProvider<OIDCIdentityProviderConfig> {

    public static final String AUTH_URL = "https://id.twitch.tv/oauth2/authorize";
    public static final String TOKEN_URL = "https://id.twitch.tv/oauth2/token";
    public static final String PROFILE_URL = "https://id.twitch.tv/oauth2/userinfo";
    public static final String DEFAULT_SCOPE = "openid user:read:email";

    private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public TwitchIdentityProvider(
        KeycloakSession session,
        TwitchIdentityProviderConfig config
    ) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL);
        config.setTokenUrl(TOKEN_URL);
        config.setUserInfoUrl(PROFILE_URL);
    }

    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected Response exchangeStoredToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        FederatedIdentityModel model = session.users().getFederatedIdentity(tokenSubject, getConfig().getAlias(), authorizedClient.getRealm());
        if (model == null || model.getToken() == null) {
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeNotLinked(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            String modelTokenString = model.getToken();

            /*
             * Convert Twitch-style access token response to OAuth 2.0
             * spec-compliant.
             */
            modelTokenString = convertFromTwitchAccessTokenResponseToSpec(modelTokenString);

            AccessTokenResponse tokenResponse = JsonSerialization.readValue(modelTokenString, AccessTokenResponse.class);
            Integer exp = (Integer) tokenResponse.getOtherClaims().get(ACCESS_TOKEN_EXPIRATION);
            if (exp != null && exp < Time.currentTime()) {
                if (tokenResponse.getRefreshToken() == null) {
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }
                String response = getRefreshTokenRequest(session, tokenResponse.getRefreshToken(),
                    getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString();
                if (response.contains("error")) {
                    logger.debugv("Error refreshing token, refresh token expiration?: {0}", response);
                    model.setToken(null);
                    session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
                    event.detail(Details.REASON, "requested_issuer token expired");
                    event.error(Errors.INVALID_TOKEN);
                    return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
                }

                /*
                 * Convert Twitch-style access token response to OAuth 2.0
                 * spec-compliant.
                 */
                response = convertFromTwitchAccessTokenResponseToSpec(response);

                AccessTokenResponse newResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
                if (newResponse.getExpiresIn() > 0) {
                    int accessTokenExpiration = Time.currentTime() + (int) newResponse.getExpiresIn();
                    newResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                }

                if (newResponse.getRefreshToken() == null && tokenResponse.getRefreshToken() != null) {
                    newResponse.setRefreshToken(tokenResponse.getRefreshToken());
                    newResponse.setRefreshExpiresIn(tokenResponse.getRefreshExpiresIn());
                }
                response = JsonSerialization.writeValueAsString(newResponse);

                String oldToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);
                if (oldToken != null && oldToken.equals(tokenResponse.getToken())) {
                    int accessTokenExpiration = newResponse.getExpiresIn() > 0 ? Time.currentTime() + (int) newResponse.getExpiresIn() : 0;
                    tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
                    tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
                    tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getToken());
                    tokenUserSession.setNote(FEDERATED_ID_TOKEN, newResponse.getIdToken());

                }
                model.setToken(response);
                tokenResponse = newResponse;
            } else if (exp != null) {
                tokenResponse.setExpiresIn(exp - Time.currentTime());
            }
            tokenResponse.setIdToken(null);
            tokenResponse.setRefreshToken(null);
            tokenResponse.setRefreshExpiresIn(0);
            tokenResponse.getOtherClaims().clear();
            tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
            tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
            event.success();
            return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void backchannelLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        if (getConfig().getLogoutUrl() == null || getConfig().getLogoutUrl().trim().equals("") || !getConfig().isBackchannelSupported())
            return;
        String idToken = getIDTokenForLogout(session, userSession);
        if (idToken == null) return;
        backchannelLogout(userSession, idToken);
    }

    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        if (getConfig().getLogoutUrl() == null || getConfig().getLogoutUrl().trim().equals("")) return null;
        String idToken = getIDTokenForLogout(session, userSession);
        if (idToken != null && getConfig().isBackchannelSupported()) {
            backchannelLogout(userSession, idToken);
            return null;
        } else {
            String sessionId = userSession.getId();
            UriBuilder logoutUri = UriBuilder.fromUri(getConfig().getLogoutUrl())
                .queryParam("state", sessionId);
            if (idToken != null) logoutUri.queryParam("id_token_hint", idToken);
            String redirect = RealmsResource.brokerUrl(uriInfo)
                .path(IdentityBrokerService.class, "getEndpoint")
                .path(OIDCEndpoint.class, "logoutResponse")
                .build(realm.getName(), getConfig().getAlias()).toString();
            logoutUri.queryParam("post_logout_redirect_uri", redirect);
            Response response = Response.status(302).location(logoutUri.build()).build();
            return response;
        }
    }

    private String getIDTokenForLogout(KeycloakSession session, UserSessionModel userSession) {
        String tokenExpirationString = userSession.getNote(FEDERATED_TOKEN_EXPIRATION);
        long exp = tokenExpirationString == null ? 0 : Long.parseLong(tokenExpirationString);
        int currentTime = Time.currentTime();
        if (exp > 0 && currentTime > exp) {
            String response = refreshTokenForLogout(session, userSession);
            AccessTokenResponse tokenResponse = null;
            try {
                /*
                 * Convert Twitch-style access token response to OAuth 2.0
                 * spec-compliant.
                 */
                response = convertFromTwitchAccessTokenResponseToSpec(response);

                tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return tokenResponse.getIdToken();
        } else {
            return userSession.getNote(FEDERATED_ID_TOKEN);

        }
    }

    @Override
    protected Response exchangeSessionToken(UriInfo uriInfo, EventBuilder event, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
        String refreshToken = tokenUserSession.getNote(FEDERATED_REFRESH_TOKEN);
        String accessToken = tokenUserSession.getNote(FEDERATED_ACCESS_TOKEN);
        String idToken = tokenUserSession.getNote(FEDERATED_ID_TOKEN);

        if (accessToken == null) {
            event.detail(Details.REASON, "requested_issuer is not linked");
            event.error(Errors.INVALID_TOKEN);
            return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
        }
        try (VaultStringSecret vaultStringSecret = session.vault().getStringSecret(getConfig().getClientSecret())) {
            long expiration = Long.parseLong(tokenUserSession.getNote(FEDERATED_TOKEN_EXPIRATION));
            if (expiration == 0 || expiration > Time.currentTime()) {
                AccessTokenResponse tokenResponse = new AccessTokenResponse();
                tokenResponse.setExpiresIn(expiration);
                tokenResponse.setToken(accessToken);
                tokenResponse.setIdToken(null);
                tokenResponse.setRefreshToken(null);
                tokenResponse.setRefreshExpiresIn(0);
                tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
                tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
                event.success();
                return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
            }
            String response = getRefreshTokenRequest(session, refreshToken, getConfig().getClientId(), vaultStringSecret.get().orElse(getConfig().getClientSecret())).asString();
            if (response.contains("error")) {
                logger.debugv("Error refreshing token, refresh token expiration?: {0}", response);
                event.detail(Details.REASON, "requested_issuer token expired");
                event.error(Errors.INVALID_TOKEN);
                return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
            }

            /*
             * Convert Twitch-style access token response to OAuth 2.0
             * spec-compliant.
             */
            response = convertFromTwitchAccessTokenResponseToSpec(response);

            AccessTokenResponse newResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
            long accessTokenExpiration = newResponse.getExpiresIn() > 0 ? Time.currentTime() + newResponse.getExpiresIn() : 0;
            tokenUserSession.setNote(FEDERATED_TOKEN_EXPIRATION, Long.toString(accessTokenExpiration));
            tokenUserSession.setNote(FEDERATED_REFRESH_TOKEN, newResponse.getRefreshToken());
            tokenUserSession.setNote(FEDERATED_ACCESS_TOKEN, newResponse.getToken());
            tokenUserSession.setNote(FEDERATED_ID_TOKEN, newResponse.getIdToken());
            newResponse.setIdToken(null);
            newResponse.setRefreshToken(null);
            newResponse.setRefreshExpiresIn(0);
            newResponse.getOtherClaims().clear();
            newResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, OAuth2Constants.ACCESS_TOKEN_TYPE);
            newResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
            event.success();
            return Response.ok(newResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        AccessTokenResponse tokenResponse = null;
        try {
            /*
             * Convert Twitch-style access token response to OAuth 2.0
             * spec-compliant.
             */
            response = convertFromTwitchAccessTokenResponseToSpec(response);

            tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode access token response.", e);
        }
        String accessToken = verifyAccessToken(tokenResponse);

        String encodedIdToken = tokenResponse.getIdToken();

        JsonWebToken idToken = validateToken(encodedIdToken);

        try {
            BrokeredIdentityContext identity = extractIdentity(tokenResponse, accessToken, idToken);

            if (!identity.getId().equals(idToken.getSubject())) {
                throw new IdentityBrokerException("Mismatch between the subject in the id_token and the subject from the user_info endpoint");
            }

            identity.getContextData().put(BROKER_NONCE_PARAM, idToken.getOtherClaims().get(OIDCLoginProtocol.NONCE_PARAM));

            if (getConfig().isStoreToken()) {
                if (tokenResponse.getExpiresIn() > 0) {
                    long accessTokenExpiration = Time.currentTime() + tokenResponse.getExpiresIn();
                    tokenResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                    response = JsonSerialization.writeValueAsString(tokenResponse);
                }
                identity.setToken(response);
            }

            return identity;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not fetch attributes from userinfo endpoint.", e);
        }
    }

    private String verifyAccessToken(AccessTokenResponse tokenResponse) {
        String accessToken = tokenResponse.getToken();

        if (accessToken == null) {
            throw new IdentityBrokerException("No access_token from server.");
        }
        return accessToken;
    }

    /**
     * Convert an OAuth 2.0 access token response formatted according to
     * <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth">
     * Twitch's authorization server implementation</a> to one that is
     * formatted according to the <a href="https://tools.ietf.org/html/rfc6749">
     * OAuth 2.0 specification</a>.
     * <p>
     * The <a href="https://tools.ietf.org/html/rfc6749#section-3.3">OAuth 2.0
     * specification</a> denotes that the scope parameter is to be expressed as
     * "a list of space-delimited, case-sensitive strings". However, in
     * Twitch's OAuth 2.0 Access Token response, the scope parameter is
     * expressed as a JSON array of strings.
     *
     * @param response OAuth 2.0 access token response formatted according to
     *                 <a href="https://dev.twitch.tv/docs/authentication/getting-tokens-oauth">
     *                 Twitch's authorization server implementation</a>
     * @return OAuth 2.0 access token response formatted according to the
     * <a href="https://tools.ietf.org/html/rfc6749"> OAuth 2.0
     * specification</a>.
     * @throws JsonProcessingException If JSON (de)serialization fails.
     */
    public String convertFromTwitchAccessTokenResponseToSpec(
        String response
    ) throws JsonProcessingException {
        Map<String, Object> accessTokenResponseMap = mapper.readValue(
            response,
            new TypeReference<Map<String, Object>>() {
            }
        );

        Object scopeObj = accessTokenResponseMap.get("scope");
        if (!(scopeObj instanceof List<?>)) {
            throw new InvalidTwitchAccessTokenResponseScopeException();
        }
        String scope = ((List<?>) scopeObj).stream()
            .map(Object::toString)
            .collect(Collectors.joining(" "));

        accessTokenResponseMap.put("scope", scope);
        return objectMapper.writeValueAsString(accessTokenResponseMap);
    }
}
