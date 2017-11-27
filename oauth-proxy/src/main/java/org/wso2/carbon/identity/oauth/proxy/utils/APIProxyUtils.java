/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.proxy.utils;

import java.util.HashMap;
import java.util.Map;

/**
 * Util class for APIProxy.
 */
public class APIProxyUtils {
    public static final String HTTPS = "https://";
    public static final String HTTP = "http://";
    public static final String HOST_REQUEST_HEADER = "host";
    public static final String AUTHORIZATION_HEADER = "AUthorization";
    public static final String AUTHORIZATION_BEARER = "Bearer %s";
    public static final String URI_QUERY_PARAMS_SEPARATOR = "?";

    /**
     * Host Mapping
     */
    public static Map<String, String> getHostMapping(){
        // TODO get from file, do it at apploading.
        Map<String, String> hostMapping = new HashMap<>();
        hostMapping.put("localhost:9443", "localhost:9443");
        return hostMapping;
    }

    /**
     * Builds the api proxy context path corresponding to the application session.
     * This should be replaced with EMPTY String when creating backend api request Uri.
     *
     * @param contextPath contextPath of the oauth proxy.
     * @param code identification code for the application session.
     * @return api proxy context path corresponding to application session.
     */
    public static String getApiProxyContextPath(String contextPath, String code){
        // Compiler uses StringBuilder in simple straight forward cases like this.
        // In Loops it is not the case, so in loops it is advised to use String Builder.
        // TODO refactor, const may be?
        return contextPath + "/api/" + code;
    }
}
