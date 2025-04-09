package hamburg.schwartau;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserClientRoleMappingMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.utils.RoleResolveUtil;


import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/*
 * Our own example protocol mapper.
 */
public class HelloWorldMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    /*
     * The ID of the token mapper. Is public, because we need this id in our data-setup project to
     * configure the protocol mapper in keycloak.
     */

    public static final String PROVIDER_ID = "oidc-hello-world-mapper";

    private static final String TOKEN_CLAIM_NAME_TOOLTIP = "usermodel.clientRoleMapping.tokenClaimName.tooltip";
    /*
     * A config which keycloak uses to display a generic dialog to configure the token.
     */
   private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {

        ProviderConfigProperty clientId = new ProviderConfigProperty();
        clientId.setName(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID);
        clientId.setLabel(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID_LABEL);
        clientId.setHelpText(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID_HELP_TEXT);
        clientId.setType(ProviderConfigProperty.CLIENT_LIST_TYPE);
        CONFIG_PROPERTIES.add(clientId);

        ProviderConfigProperty clientRolePrefix = new ProviderConfigProperty();
        clientRolePrefix.setName(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_ROLE_PREFIX);
        clientRolePrefix.setLabel(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_ROLE_PREFIX_LABEL);
        clientRolePrefix.setHelpText(ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_ROLE_PREFIX_HELP_TEXT);
        clientRolePrefix.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(clientRolePrefix);

        ProviderConfigProperty multiValued = new ProviderConfigProperty();
        multiValued.setName(ProtocolMapperUtils.MULTIVALUED);
        multiValued.setLabel(ProtocolMapperUtils.MULTIVALUED_LABEL);
        multiValued.setHelpText(ProtocolMapperUtils.MULTIVALUED_HELP_TEXT);
        multiValued.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        multiValued.setDefaultValue("true");
        CONFIG_PROPERTIES.add(multiValued);

        OIDCAttributeMapperHelper.addAttributeConfig(CONFIG_PROPERTIES, HelloWorldMapper.class);

        // Alternative tooltip for the 'Token Claim Name'
        for (ProviderConfigProperty prop : CONFIG_PROPERTIES) {
            if (OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME.equals(prop.getName())) {
                prop.setHelpText(TOKEN_CLAIM_NAME_TOOLTIP);
            }
        }
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getDisplayType() {
        return "Hello World Mapper";
    }

    @Override
    public String getHelpText() {
        return "Adds a hello world text to the claim";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(final IDToken token,
                            final ProtocolMapperModel mappingModel,
                            final UserSessionModel userSession,
                            final KeycloakSession keycloakSession,
                            final ClientSessionContext clientSessionCtx) {
        
        // Filter composite roles
        List<String> topLevelRoles = clientSessionCtx.getRolesStream()
                .filter(RoleModel::isComposite)
                .map(RoleModel::getName)
                .collect(Collectors.toList());

        // Manually set the claim in the token
        token.getOtherClaims().put(mappingModel.getName(), new ArrayList<>() {{
            add("Roles: " + String.join(", ", topLevelRoles));
        }});
    }

}
