package com.wso2.carbon.custom.user.store.manager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.user.api.Properties;
import org.wso2.carbon.user.api.Property;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;

public class CustomUserStoreManager extends JDBCUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);

    public static final String PROPERTY_SERVICE_PROVIDERS_TO_ALLOW = "Service Providers to Allow";

    public CustomUserStoreManager() {
    }

    public CustomUserStoreManager(org.wso2.carbon.user.api.RealmConfiguration realmConfig,
                                  Map<String, Object> properties,
                                  ClaimManager claimManager,
                                  ProfileConfigurationManager profileManager,
                                  UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId, false);
    }

    @Override
    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {

        String spName = IdentityApplicationManagementUtil.getSPFromThreadLocal();
        if (log.isDebugEnabled()) {
            log.debug("Authentication request from SP=\'" + spName + "\'");
        }
        String spsToAllow = this.realmConfig.getUserStoreProperty(PROPERTY_SERVICE_PROVIDERS_TO_ALLOW);
        ArrayList<String> spWhiteList = new ArrayList<String>();
        if (spsToAllow != null) {
            spWhiteList = new ArrayList<String>(Arrays.asList(spsToAllow.split(",")));
        }
        boolean isSpWhiteListed = false;
        for (int i = 0; i < spWhiteList.size(); i++) {
            if (spWhiteList.get(i) != null && spWhiteList.get(i).equals(spName)) {
                log.debug("SP=\'" + spName + "\' is white listed");
                isSpWhiteListed = true;
                break;
            }
        }
        if (!isSpWhiteListed) {
            return false;
        }
        return super.doAuthenticate(userName, credential);
    }

    @Override
    public Properties getDefaultUserStoreProperties() {
        Properties properties = super.getDefaultUserStoreProperties();

        ArrayList<Property> mandatoryProperties = new ArrayList<Property>(Arrays.asList(properties.
                getMandatoryProperties()));

        mandatoryProperties.add(new Property(PROPERTY_SERVICE_PROVIDERS_TO_ALLOW, "",
                "List of service providers for which the user store should be allowed", null));
        properties.setMandatoryProperties(mandatoryProperties.toArray(new Property[mandatoryProperties.size()]));
        return properties;
    }
}