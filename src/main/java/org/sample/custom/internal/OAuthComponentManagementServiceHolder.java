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

import org.wso2.carbon.registry.api.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;


public class OAuthComponentManagementServiceHolder {

    private static OAuthComponentManagementServiceHolder instance = new
            OAuthComponentManagementServiceHolder();

    private  RealmService realmService;
    private  RegistryService registryService;


    private OAuthComponentManagementServiceHolder() {
    }

    public static OAuthComponentManagementServiceHolder getInstance() {
        return instance;
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    public  RegistryService getRegistryService() {
        return registryService;
    }

    public  void setRegistryService(RegistryService registryService) {
        this.registryService = registryService;
    }
}
