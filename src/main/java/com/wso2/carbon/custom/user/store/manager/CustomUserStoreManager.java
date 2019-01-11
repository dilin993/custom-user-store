package com.wso2.carbon.custom.user.store.manager;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;

public class CustomUserStoreManager extends JDBCUserStoreManager {
    private static Log log = LogFactory.getLog(CustomUserStoreManager.class);

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
        if (!"Mainframe".equals(spName))   {
            return false;
        }
        return super.doAuthenticate(userName, credential);
    }

}