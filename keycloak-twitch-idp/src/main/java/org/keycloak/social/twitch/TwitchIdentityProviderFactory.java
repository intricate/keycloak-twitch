package org.keycloak.social.twitch;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Twitch identity provider factory.
 */
public class TwitchIdentityProviderFactory
    extends AbstractIdentityProviderFactory<TwitchIdentityProvider>
    implements SocialIdentityProviderFactory<TwitchIdentityProvider> {

    public static final String PROVIDER_NAME = "Twitch";
    public static final String PROVIDER_ID = "twitch";

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public TwitchIdentityProvider create(
        KeycloakSession session,
        IdentityProviderModel model
    ) {
        return new TwitchIdentityProvider(
            session,
            new TwitchIdentityProviderConfig(model)
        );
    }

    @Override
    public TwitchIdentityProviderConfig createConfig() {
        return new TwitchIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
