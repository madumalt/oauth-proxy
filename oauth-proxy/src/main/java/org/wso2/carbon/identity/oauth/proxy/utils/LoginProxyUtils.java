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

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthClientResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;
import org.apache.commons.lang.StringUtils;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;

import java.util.regex.Pattern;

/**
 * Util Class for LoginProxy.
 */
public class LoginProxyUtils {
    public static final String IS_AUTHORIZATION_EP = "/oauth2/authorize";
    public static final String IS_TOKEN_EP = "/oauth2/token";
    public static final String IS_SERVER_EP = "is_server_ep";
    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String OAUTH_GRANT_TYPE_CODE = "code";
    public static final String SCOPE = "scope.";
    public static final String OPENID_SCOPE = "openid";
    public static final String AUTHENTICATED = "authenticated";
    public static final String AUTHENTICATED_SCOPES = "authenticated_scopes";
    private static final String SP_CALLBACK_URL_MAPPING = "sp_callback_url_mapping.";
    private static final String SP_CLOGOUT_URL_MAPPING = "sp_logout_url_mapping.";
    private static final String PROXY_CALLBACK_URL = "proxy_callback_url";

    /**
     * Construct the cookie name to store SPA name.
     *
     * @param code appSessionId code
     * @return String SPA_NAME const appended to code
     */
    public static String getSpaNameCookieName(String code) {
        return code + "." + ProxyUtils.SPA_NAME;
    }

    public static String getAuthzEp() {
        return ProxyUtils.getProperty(IS_SERVER_EP) + IS_AUTHORIZATION_EP;
    }

    public static String getTokenEp() {
        return ProxyUtils.getProperty(IS_SERVER_EP) + IS_TOKEN_EP;
    }

    /**
     * Gives the client id corresponding to the service provider in IS.
     * Try to retrieve SPA Name specific client Id.
     * If fails, then get the proxy client Id.
     *
     * @param spaName application client name
     * @return clientId of the IS service provider
     */
    public static String getConsumerKey(String spaName) {
        String spaSpClientId = ProxyUtils.getProperty(CLIENT_ID + "." + spaName);
        return StringUtils.isNotEmpty(spaSpClientId) ? spaSpClientId : ProxyUtils.getProperty(CLIENT_ID);
    }

    /**
     * Gives the client secret corresponding to the service provider in IS.
     * Try to retrieve SPA Name specific client secret.
     * If fails, then get the proxy client secret.
     *
     * @param spaName application client name
     * @return client secret of the IS service provider
     */
    public static String getConsumerSecret(String spaName) {
        String spaSpClientSecret = ProxyUtils.getProperty(CLIENT_SECRET + "." + spaName);
        return StringUtils.isNotEmpty(spaSpClientSecret) ? spaSpClientSecret : ProxyUtils.getProperty(CLIENT_SECRET);
    }

    public static String getAuthzGrantType() {
        return OAUTH_GRANT_TYPE_CODE;
    }

    public static String getScope(String spaName) {
        return ProxyUtils.getProperty(SCOPE + spaName.toLowerCase());

    }

    public static String getSpaCallbackUrl(String spaName) {
        return ProxyUtils.getProperty(SP_CALLBACK_URL_MAPPING + spaName.toLowerCase());
    }

    public static String getSpaLogoutUrl(String spaName) {
        return ProxyUtils.getProperty(SP_CLOGOUT_URL_MAPPING + spaName.toLowerCase());
    }

    public static String getProxyCallbackUrl() {
        return ProxyUtils.getProperty(PROXY_CALLBACK_URL);
    }

    /**
     * Obtain an access token from authorization server in exchange of oath code.
     *
     * @param tokenEndpoint token endpoint of the authorization server
     * @param consumerKey consumer key corresponding to the service provider at authorization server
     * @param consumerSecret consumer secret corresponding to the service provider at authorization server
     * @param callbackUrl callback Url
     * @param oauthCode authorization code
     *
     * @return OAuthClientResponse
     * @throws OAuthProxyException on failure in obtaining a response.
     */
    public static OAuthClientResponse getAccessToken  (String tokenEndpoint, String consumerKey, String
            consumerSecret, String callbackUrl, String oauthCode) throws OAuthProxyException {
        OAuthClientRequest accessRequest = null;

        // Create an OAuth 2.0 token request.
        try {
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndpoint).setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(consumerKey).setClientSecret(consumerSecret).setRedirectURI(callbackUrl).setCode(oauthCode)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            throw new OAuthProxyException("Error while building the access token request.");
        }

        // Create an OAuth 2.0 client that uses custom HTTP client under the hood
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());

        // Talk to the OAuth token end-point of identity server to get the OAuth access, refresh, and id tokens.
        try {
            return oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException | OAuthProblemException e) {
            throw new OAuthProxyException("Error while obtaining an access token from the authorization server.", e);
        }
    }

    /**
     * Builds the jwt from the OAuth token endpoint response.
     *
     * @param oAuthResponse OAuth token end-point response
     * @param spaName name of the SPA
     * @return JSONObject jwt
     * @throws OAuthProxyException on failure at creation of jwt.
     */
    public static JSONObject buildLoginJwt (OAuthClientResponse oAuthResponse, String spaName) throws OAuthProxyException {

        // read the access token from the OAuth token end-point response.
        String accessToken = oAuthResponse.getParam(ProxyUtils.ACCESS_TOKEN);
        // read the refresh token from the OAuth token end-point response.
        String refreshToken = oAuthResponse.getParam(ProxyUtils.REFRESH_TOKEN);
        // read the expiration from the OAuth token endpoint response.
        long expiration = Long.parseLong(oAuthResponse.getParam(ProxyUtils.EXPIRATION));
        // read the id token from the OAuth token end-point response.
        String idToken = oAuthResponse.getParam(ProxyUtils.ID_TOKEN);

        if (idToken != null) {
            // extract out the content of the JWT, which comes in the id token.
            String[] idTkElements = idToken.split(Pattern.quote("."));
            idToken = idTkElements[1];
        }

        // create a JSON object aggregating OAuth access token, refresh token and id token
        JSONObject json = new JSONObject();

        try {
            json.put(ProxyUtils.ID_TOKEN, idToken);
            json.put(ProxyUtils.ACCESS_TOKEN, accessToken);
            json.put(ProxyUtils.REFRESH_TOKEN, refreshToken);
            json.put(ProxyUtils.SPA_NAME, spaName);
            json.put(ProxyUtils.EXPIRATION, new Long(expiration));
            return json;
        } catch (JSONException e) {
            throw new OAuthProxyException("Error while building the login jwt from the OAuth token endpoint response" +
                    ".", e);
        }
    }

    /**
     * Include openid scope if it is not already in the given scope.
     *
     * @param scope oauth scopes separated by comma
     * @return oauth scopes openid inclusive
     */
    public static String getOpenidInclusiveScope (String scope) {
        if (StringUtils.isEmpty(scope)) {
            return LoginProxyUtils.OPENID_SCOPE;
        } else if (scope.contains(LoginProxyUtils.OPENID_SCOPE)) {
            return scope;
        } else {
            return LoginProxyUtils.OPENID_SCOPE +  "," + scope;
        }
    }
}
