package hamburg.schwartau;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.FullNameMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.mockito.Mockito;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

public class HelloWorldMapperTest {

    static final String CLAIM_NAME = "haandlerIdClaimNameExample";

    @Test
    public void shouldTokenMapperDisplayCategory() {
        final String tokenMapperDisplayCategory = new FullNameMapper().getDisplayCategory();
        assertThat(new HelloWorldMapper().getDisplayCategory()).isEqualTo(tokenMapperDisplayCategory);
    }

    @Test
    public void shouldHaveDisplayType() {
        assertThat(new HelloWorldMapper().getDisplayType()).isNotBlank();
    }

    @Test
    public void shouldHaveHelpText() {
        assertThat(new HelloWorldMapper().getHelpText()).isNotBlank();
    }

    @Test
    public void shouldHaveIdId() {
        assertThat(new HelloWorldMapper().getId()).isNotBlank();
    }

    @Test
    public void shouldHaveProperties() {
        final List<String> configPropertyNames = new HelloWorldMapper().getConfigProperties().stream()
                .map(ProviderConfigProperty::getName)
                .collect(Collectors.toList());
        assertThat(configPropertyNames).containsExactly(
            ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_CLIENT_ID,
            ProtocolMapperUtils.USER_MODEL_CLIENT_ROLE_MAPPING_ROLE_PREFIX,
            ProtocolMapperUtils.MULTIVALUED,
            OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME, 
            OIDCAttributeMapperHelper.JSON_TYPE, 
            OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, 
            OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, 
            OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO);
    }
}