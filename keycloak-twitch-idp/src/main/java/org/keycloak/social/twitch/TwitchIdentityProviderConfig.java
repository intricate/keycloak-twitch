package org.keycloak.social.twitch;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * Twitch identity provider configuration.
 */
public class TwitchIdentityProviderConfig extends OIDCIdentityProviderConfig {

    public TwitchIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public TwitchIdentityProviderConfig() {
    }
}
