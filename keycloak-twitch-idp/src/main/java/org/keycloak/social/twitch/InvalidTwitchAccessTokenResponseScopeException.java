package org.keycloak.social.twitch;

public class InvalidTwitchAccessTokenResponseScopeException
    extends RuntimeException {

    public InvalidTwitchAccessTokenResponseScopeException() {
        super("Invalid \"scope\" provided in Twitch access token response.");
    }
}
