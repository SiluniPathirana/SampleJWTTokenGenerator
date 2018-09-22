/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein is strictly forbidden, unless permitted by WSO2 in accordance with
 * the WSO2 Commercial License available at http://wso2.com/licenses. For specific
 * language governing the permissions and limitations under this license,
 * please see the license as well as any agreement you’ve entered into with
 * WSO2 governing the purchase of this software and any associated services.
 */

package org.sample.custom.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sample.custom.CustomJWTTokenGenerator;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.oauth2.authcontext.AuthorizationContextTokenGenerator;
import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.custom.sample" immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 */

public class OAuthCallbackExtensionComponent {

    private static Log log = LogFactory.getLog(OAuthCallbackExtensionComponent.class);
    private static RealmService realmService;
    private static RegistryService registryService;

    protected void activate(ComponentContext ctxt) {
        try {
            CustomJWTTokenGenerator jwtTokenGenerator = new CustomJWTTokenGenerator();
            ctxt.getBundleContext().registerService(AuthorizationContextTokenGenerator.class.getName(),
                    jwtTokenGenerator, null);
            log.info("OAuth callback extension component activated successfully.");
        } catch (Exception e) {
            log.error("Failed to activate OAuth callback extension component ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("OAuth callback extension component is deactivated ");
        }
    }

    protected void setRealmService(RealmService realmService) {
        OAuthCallbackExtensionComponent.realmService = realmService;
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the OAuth callback extension component");
        }
        OAuthComponentManagementServiceHolder.getInstance().setRealmService(realmService);

    }

    protected void unsetRealmService(RealmService realmService) {
        OAuthCallbackExtensionComponent.realmService = null;
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the OAuth callback extension component");
        }
        OAuthComponentManagementServiceHolder.getInstance().setRealmService(null);

    }

    public static RealmService getRealmService() {
        return OAuthComponentManagementServiceHolder.getInstance().getRealmService();

    }

    protected void setRegistryService(RegistryService registryService) {
        OAuthCallbackExtensionComponent.registryService = registryService;
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is set in the OAuth callback extension component");
        }
        OAuthComponentManagementServiceHolder.getInstance().setRealmService(realmService);

    }

    protected void unsetRegistryService(RegistryService registryService) {
        OAuthCallbackExtensionComponent.registryService = null;
        if (log.isDebugEnabled()) {
            log.debug("RegistryService is unset in the OAuth callback extension component");
        }
        OAuthComponentManagementServiceHolder.getInstance().setRealmService(null);

    }

    public static RegistryService  getRegistryService() {
        return OAuthComponentManagementServiceHolder.getInstance().getRegistryService();

    }
}
