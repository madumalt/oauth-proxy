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

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.regexp.RE;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.exceptions.InvalidInputException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OperationFailureExceptions;
import org.wso2.carbon.identity.oauth.proxy.exceptions.ProxyConfigurationException;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Util class for APIProxy.
 */
public class APIProxyUtils {
    public static final String HOST_NAME_MAPPING_FOR_SPA = "host_name_mapping.%s.%s";
    public static final String SPA_SESSION_ID_HEADER = "Spa-Session-Id";

    /**
     * Retrieve the host name mapping for the given host of the respective spaName.
     *
     * @param spaName single page application name
     * @param host host name to be mapped
     * @return mapped host name | null
     */
    public static String getMappedHost(String spaName, String host){
        return ProxyUtils.getProperty(String.format(HOST_NAME_MAPPING_FOR_SPA, spaName, host));
    }

    /**
     * Builds the api proxy context path corresponding to the application session.
     * This should be replaced with EMPTY String when creating backend api request Uri.
     *
     * @param contextPath contextPath of the oauth proxy.
     * @return api proxy context path corresponding to application session.
     */
    public static String getApiProxyContextPath(String contextPath){
        // Compiler uses StringBuilder in simple straight forward cases like this.
        // In Loops it is not the case, so in loops it is advised to use String Builder.
        // TODO refactor, const may be?
        return contextPath + "/api";
    }

    /**
     * Extract the access_token from the corresponding cookie in the request.
     *
     * @param request        HttpServletRequest received from the client
     * @param appSeesionCode identification code for the application session
     * @return String access_token
     * @throws InvalidInputException by ProxyUtils.getDecryptedJwt
     * @throws OperationFailureExceptions by this method or ProxyUtils.getDecryptedJwt
     * @throws ProxyConfigurationException by ProxyUtils.getDecryptedJwt
     */
    public static String getAccessToken(HttpServletRequest request, String appSeesionCode)
            throws InvalidInputException, OperationFailureExceptions, ProxyConfigurationException {
        try {
            JSONObject decryptedJwt = ProxyUtils.getDecryptedJwt(request, appSeesionCode);
            return decryptedJwt.getString(ProxyUtils.ACCESS_TOKEN);
        } catch (JSONException e) {
            throw new OperationFailureExceptions("Error while retrieving " + ProxyUtils.ACCESS_TOKEN
                    + "from jwt JSONObject.", e);
        }
    }

    /**
     * Build bearer authorized GET request, execute, and return the response.
     *
     * @param Url URL for GET request
     * @param accessToken Bearer token
     * @return
     */
    public static Response doBearerAuthorizedGetCall(String Url, String accessToken) throws OperationFailureExceptions {

        // Build GET request with the given url.
        HttpMethod httpMethod = new GetMethod(Url);

        // Set Authorization header.
        Header authorizationHeader = new Header(ProxyUtils.AUTHORIZATION_HEADER,
                String.format(ProxyUtils.AUTHORIZATION_BEARER, accessToken));
        httpMethod.addRequestHeader(authorizationHeader);

        HttpClient httpClient = new HttpClient();
        try {
            // Execute the GET request.
            int statusCode = httpClient.executeMethod(httpMethod);

            // TODO what else should be there in the response? also look into getResponseBodyAsStream.
            // Build the response from the response received.
            Response response = Response.status(statusCode).entity(httpMethod.getResponseBodyAsString()).build();
            return response;
        } catch (IOException e) {
            throw new OperationFailureExceptions("Error while calling: " + httpMethod.getPath(), e);
        } finally {
            if (httpMethod != null) {
                httpMethod.releaseConnection();
            }
        }
    }
}
