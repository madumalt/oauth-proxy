
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

package org.wso2.carbon.identity.oauth.proxy;

import java.io.IOException;
import java.util.Calendar;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthClientResponse;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.exceptions.InvalidInputException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OperationFailureExceptions;
import org.wso2.carbon.identity.oauth.proxy.exceptions.ProxyConfigurationException;
import org.wso2.carbon.identity.oauth.proxy.utils.APIProxyUtils;
import org.wso2.carbon.identity.oauth.proxy.utils.LoginProxyUtils;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyFaultCodes;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyUtils;

/**
 * This endpoint acts a proxy end-point single page applications(SPA). to authenticate a user, the SPA must do a GET to
 * the /login end-point with spaName and spaSessionId parameters.
 * The spaName is a unique identifier for each SPA, and the proxy application should be aware of that identifier. The
 * LoginProxy end-point uses the spaName later to load the callback URL corresponding to the SPA.
 * The spaSessionId is a random generated number by the SPA. SPA should guarantee its randomness. each time the SPA
 * gets rendered on the browser it has to generate the spaSessionId. Spas should not uses statically configured code
 * values.
 */
@Consumes({ MediaType.APPLICATION_JSON })
@Produces(MediaType.APPLICATION_JSON)
public class LoginProxy {

    private final static Log log = LogFactory.getLog(LoginProxy.class);

    // keeps track of HttpServletRequest and HttpServletResponse
    @Context
    private MessageContext context;

    /**
     * The SPA should call this API to initiate user authentication. This method will redirect the user to the
     * identity server's OAuth 2.0 authorization endpoint. The value of the spaName parameter will be written to a
     * cookie, so it can be accessed when get redirected back from the identity server, after user authentication.
     *
     * @param spaName      is a unique identifier for each SPA, and the proxy application should be aware of that
     *                     identifier.the proxy end-point uses the spaName later to load the callback URL
     *                     corresponding to the SPA.
     * @param spaSessionId each times the SPA gets rendered on the browser has to generate the spaSessionId.Spas
     *                     should not uses statically configured spaSessionId values.
     * @return Response
     */
    @Path("login")
    @GET
    public Response getAuthzCode(@QueryParam(LoginProxyUtils.SPA_NAME) String spaName,
                                 @QueryParam(LoginProxyUtils.SESSION_ID) String spaSessionId) {

        if (StringUtils.isEmpty(spaName)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the spaName cannot be null.");
        }

        if (StringUtils.isEmpty(spaSessionId)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the session-id cannot be null.");
        }

        HttpServletResponse resp = context.getHttpServletResponse();

        // Loads the client key corresponding to the SPA. you do not need to have SPA specific consumer keys, rather can
        // use one client key for all the SPAs. you get the consumer key from the identity server, at the time you
        // register the service provider, and configure it in oauth_proxy.properties file.
        String consumerKey = LoginProxyUtils.getConsumerKey(spaName);
        // This is the OpenID 2.0 authorization end-point of the identity server.
        String authzEndpoint = LoginProxyUtils.getAuthzEp();
        // Get the grant type. the proxy works only with the authorization spaSessionId grant type.
        String authzGrantType = LoginProxyUtils.getAuthzGrantType();
        // get the scope associated with the SPA. each SPA can define its own scopes in the oauth_proxy.properties file,
        // but in each case OPENID is used as a mandatory scope value.
        String scope = LoginProxyUtils.getOpenidInclusiveScope(LoginProxyUtils.getScope(spaName));

        // Load the callback URL of the proxy. there is only one callback URL. even when you create multiple service
        // providers in identity server to get multiple client key/client secret pairs, the callback URL would be the
        // same.
        String callbackUrl = LoginProxyUtils.getProxyCallbackUrl();

        OAuthClientRequest authzRequest = null;
        try {
            // Create a cookie under the proxy domain having ${spaSessionId}.spa_name as the key
            // and  the spaName as the value.
            Cookie cookie = new Cookie(LoginProxyUtils.getSpaNameCookieName(spaSessionId), spaName);
            // This cookie is only accessible by HTTPS transport.
            cookie.setSecure(true);
            // TODO think of an expiry time for the cookie.
            // Add cookie to the response.
            resp.addCookie(cookie);

            // Create the OAuth 2.0 request with all necessary parameters. the spaSessionId passed by the SPA is set
            // as the state - so the identity server will return it back with the OAuth response. we use the value of
            // the spaSessionId (or the state here) to retrieve the cookie later. this is done in a way to make this
            // proxy application state-less.
            authzRequest = OAuthClientRequest.authorizationLocation(authzEndpoint).setClientId(consumerKey)
                    .setRedirectURI(callbackUrl).setResponseType(authzGrantType).setScope(scope).setState(spaSessionId)
                    .buildQueryMessage();
        } catch (OAuthSystemException e) {
            log.error(e);
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }

        try {
            // Redirects the user to the identity server's authorization end-point.
            resp.sendRedirect(authzRequest.getLocationUri());
            // Once redirection is successful no need to return a response thus returning null.
            return null;
        } catch (IOException e) {
            log.error(e);
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }

    }

    /**
     * This method gets fired when the identity server returns back the authorization oauthCode, after authenticating
     * the user. In addition to the authorization oauthCode, the response from the identity server must also include
     * the state parameter, which contains the value we set when we initiate the authorization grant.
     *
     * @param oauthCode the authorization oauthCode generated by the identity server. the proxy application will
     *                  exchange this token to get an access token from the identity server.
     * @param state     this is the same value we set as state, when we initiate the authorization grant request to
     *                  the identity server.
     * @return Response
     */
    @Path("callback")
    @GET
    public Response handleCallback(@QueryParam("code") String oauthCode, @QueryParam("state") String state) {

        if (StringUtils.isEmpty(oauthCode)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the oauthCode cannot be empty.");
        }

        if (StringUtils.isEmpty(state)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the state cannot be empty.");
        }

        HttpServletResponse resp = context.getHttpServletResponse();
        HttpServletRequest req = context.getHttpServletRequest();
        Cookie[] cookies = req.getCookies();
        // Try to load the cookie corresponding to the value of the state.
        String spaName = ProxyUtils.getCookievalue(cookies, LoginProxyUtils.getSpaNameCookieName(state));

        if (StringUtils.isEmpty(spaName)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "No valid cookie holding spa-name is found.");
        }

        // Loads the client key corresponding to the SPA. You do not need to have SPA specific consumer keys, rather
        // can use one client key for all the SPAs. You get the consumer key from the identity server, at the time you
        // register the service provider, and configure it in oauth_proxy.properties file.
        String consumerKey = LoginProxyUtils.getConsumerKey(spaName);
        // Loads the client secret corresponding to the SPA. You do not need to have SPA specific client secret, rather
        // can use one client secret for all the SPAs. You get the client secret from the identity server, at the time
        // you register the service provider, and configure it in oauth_proxy.properties file.
        String consumerSecret = LoginProxyUtils.getConsumerSecret(spaName);
        // This is the OAuth 2.0 token end-point of the identity server.
        String tokenEndpoint = LoginProxyUtils.getTokenEp();
        // Load the callback URL of the proxy. There is only one callback URL. Even when you create multiple service
        // providers in identity server to get multiple client key/client secret pairs, the callback URL would be the
        // same.
        String callbackUrl = LoginProxyUtils.getProxyCallbackUrl();

        JSONObject jwt = null;
        try {
            // Obtain an access token by exchanging the oauth oauthCode.
            OAuthClientResponse oAuthResponse = LoginProxyUtils.getAccessToken(tokenEndpoint, consumerKey,
                    consumerSecret, callbackUrl, oauthCode);
            // Build the login jwt from the OAuth token endpoint response.
            jwt = LoginProxyUtils.buildLoginJwt(oAuthResponse, spaName);
        } catch (OperationFailureExceptions e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }

        try {
            // Encrypt the JSON message.
            String encryptedCookieValue = ProxyUtils.encrypt(jwt.toString());
            // Create a cookie under the proxy domain with the encrypted message. Cookie name is set to the value of
            // the spaSessionId (here it is state because proxy passed spaSessionId as the state of the
            // authentication request to the Identity Server).
            Cookie cookie = new Cookie(state, encryptedCookieValue);
            // The cookie is only accessible by the HTTPS transport.
            cookie.setSecure(true);
            // TODO think of an expiry time.
            // Add cookie to the response.
            resp.addCookie(cookie);
            // Get the SPA callback URL. Each SPA has its own callback URL, which is defined in the
            // oauth_proxy.properties file
            resp.sendRedirect(LoginProxyUtils.getSpaCallbackUrl(spaName));
            // Once redirection is successful no need to return a response thus returning null.
            return null;
        } catch (OAuthProxyException | IOException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }
    }

    /**
     * Clears all the cookies corresponding to the spa session.
     * 
     * @param spaSessionId Id for spa session.
     * @return Response
     */
    @Path("logout")
    @GET
    public Response logout(@QueryParam(LoginProxyUtils.SESSION_ID) String spaSessionId) {

        if (StringUtils.isEmpty(spaSessionId)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the session-id cannot be null.");
        }

        HttpServletRequest req = context.getHttpServletRequest();
        HttpServletResponse resp = context.getHttpServletResponse();
        Cookie[] cookies = req.getCookies();

        // Get spa name from the corresponding cookie. Spa Name is required to get the redirecting url.
        // Redirection Url of each spa should be configured in the oauth_proxy.properties file.
        String spaName = ProxyUtils.getCookievalue(cookies, LoginProxyUtils.getSpaNameCookieName(spaSessionId));

        // Clear all the cookies corresponding to the spaSessionId.
        clearCookies(resp, cookies, spaSessionId);

        if (StringUtils.isEmpty(spaName)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_001, "No corresponding spa-name found for the provided spaSessionId");
        }

        try {
            resp.sendRedirect(LoginProxyUtils.getSpaLogoutUrl(spaName));
            return null;
        } catch (IOException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }
    }

    /**
     * This API is invoked by the SPA to get user information. The proxy decrypts the cookie (the one that having the
     * value of the spaSessionId parameter as its name) to extract out the user information and will send back a JSON
     * response to the SPA.
     * 
     * @param spaSessionId Id for spa session.
     * @return Response
     */
    @Path("users")
    @GET
    public Response getUserInfo(@QueryParam(LoginProxyUtils.SESSION_ID) String spaSessionId) {

        if (StringUtils.isEmpty(spaSessionId)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the session-id cannot be null.");
        }

        try {
            // Extract the jwt from the corresponding cookie.
            JSONObject jwt = ProxyUtils.getDecryptedJwt(context.getHttpServletRequest(), spaSessionId);
            // Load the user info from the JSON object.
            String userInfo = jwt.getString(ProxyUtils.ID_TOKEN);
            // Send back the base64url-decode user info response to the SPA.
            return Response.ok().entity(ProxyUtils.base64UrlDecode(userInfo)).build();
        } catch (InvalidInputException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    e.getMessage());
        } catch (ProxyConfigurationException | OperationFailureExceptions | JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR, ProxyFaultCodes
                    .ERROR_003, e.getMessage());
        }
    }

    /**
     * This will be invoked by the SPA to check whether the user is authenticated.
     * If the id_token expiry time is higher than the current time will send {authenticated: true}.
     * Otherwise will send {authenticated: false}.
     *
     * @param spaSessionId Id for spa session.
     * @return Response {authenticated: true/false}
     */
    @Path("authenticated")
    @GET
    public Response validateUserAuthentication(@QueryParam(LoginProxyUtils.SESSION_ID) String spaSessionId) {

        // AppSessionId spaSessionId cannot be null.
        if (StringUtils.isEmpty(spaSessionId)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the session-id cannot be empty.");
        }

        HttpServletRequest req = context.getHttpServletRequest();
        Cookie[] cookies = req.getCookies();
        // Try to load the cookie corresponding to the value of the spaSessionId.
        String encryptedCookieValue = ProxyUtils.getCookievalue(cookies, spaSessionId);

        // No cookie corresponding to the spaSessionId means, not authenticated.
        if (StringUtils.isEmpty(encryptedCookieValue)) {
            return buildAuthenticatedResponse(false);
        }

        // Decrypt the corresponding cookie and validate the authentication.
        try {
            JSONObject cookieValue = new JSONObject(ProxyUtils.decrypt(encryptedCookieValue));

            String accessToken = cookieValue.getString(ProxyUtils.ACCESS_TOKEN);
            String idToken = cookieValue.getString(ProxyUtils.ID_TOKEN);

            if (StringUtils.isNotEmpty(accessToken) && StringUtils.isNotEmpty(idToken)) {
                JSONObject idTokenInfo = new JSONObject(ProxyUtils.base64UrlDecode(idToken));
                // Since id_token expiry time and issued time are in seconds need to get current time also in seconds.
                long currentTime = Calendar.getInstance().getTimeInMillis() /
                        ProxyUtils.MILLIS_TO_SECONDS_CONVERT_FACTOR;
                long expiryTime = idTokenInfo.getLong(ProxyUtils.ID_TOKEN_EXPIRY_TIME);
                long issuedTime = idTokenInfo.getLong(ProxyUtils.ID_TOKEN_ISSUED_TIME);

                if (issuedTime < currentTime && currentTime < expiryTime) {
                    return buildAuthenticatedResponse(true);
                } else {
                    return buildAuthenticatedResponse(false);
                }
            } else {
                // No access_token or no id_token means not authenticated.
                return buildAuthenticatedResponse(false);
            }
        } catch (ProxyConfigurationException | OperationFailureExceptions | JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }
    }

    /**
     * This API is invoked by the SPA to get user information. The proxy decrypts the cookie (the one that having the
     * value of the spaSessionId parameter as its name) to extract out the access_token. Thereafter calls the  Identity
     * Server's oauth2/userinfo endpoint with the access_token and passes the response to the SPA client.
     *
     * @param spaSessionId Id for spa session.
     * @return Response
     */
    @Path("userinfo")
    @GET
    public Response proxyUserInfo(@QueryParam(LoginProxyUtils.SESSION_ID) String spaSessionId,
                                  @QueryParam(LoginProxyUtils.SCOPE) String scope) {
        if (StringUtils.isEmpty(spaSessionId)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the session-id cannot be null.");
        }

        try {
            // Extract the access_token from the corresponding cookie holding the jwt.
            String accessToken = APIProxyUtils.getAccessToken(context.getHttpServletRequest(), spaSessionId);

            // Respond with an error when no access_token is found.
            if (StringUtils.isEmpty(accessToken)) {
                return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.FORBIDDEN, ProxyFaultCodes.ERROR_011,
                        "No access_token found in the cookie holding the jwt.");
            }

            // Build the url for <IS>/oauth2/userinfo?scope=<scopes separated by commas>
            String userinfoUrl = buildUserinfoRequestUrl(LoginProxyUtils.getUserinfoEp(),
                    LoginProxyUtils.getOpenidInclusiveScope(scope));

            // Do the GET call to the IS userinfo endpoint with the access token.
            return APIProxyUtils.doBearerAuthorizedGetCall(userinfoUrl, accessToken);

        } catch (InvalidInputException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    e.getMessage());
        } catch (ProxyConfigurationException | OperationFailureExceptions e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR, ProxyFaultCodes
                    .ERROR_003, e.getMessage());
        }
    }

    /**
     * Clears all the cookies corresponding to appSessionId code
     * by setting MaxAge to 0 and value to empty and adding that cookie to the response.
     *
     * @param response HttpServletResponse
     * @param cookies array of Cookie
     * @param code appSessionId cookie
     */
    private void clearCookies(HttpServletResponse response, Cookie[] cookies, String code) {
        if (cookies != null && cookies.length > 0) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(code)
                        || cookie.getName().equals(LoginProxyUtils.getSpaNameCookieName(code))) {
                    cookie.setMaxAge(0);
                    cookie.setValue("");
                    response.addCookie(cookie);
                }
            }
        }
    }

    /**
     * Build the response for Path: authenticated.
     *
     * @param isAuthenticated specify whether the user has a valid access token
     * @return Response
     */
    private static Response buildAuthenticatedResponse(Boolean isAuthenticated) {
        JSONObject responseJson = new JSONObject();
        try {
            responseJson.put(LoginProxyUtils.AUTHENTICATED, isAuthenticated);
            return Response.ok(responseJson.toString(), MediaType.APPLICATION_JSON_TYPE).build();
        } catch (JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }
    }

    /**
     * Builds the userinfo request Url by appending scope query param.
     *
     * @param userinfoEndpoint endpoint
     * @param scope scope query param value
     * @return String url with scope query param
     */
    private static String buildUserinfoRequestUrl(String userinfoEndpoint, String scope) {
        return userinfoEndpoint + ProxyUtils.URI_QUERY_PARAMS_SEPARATOR + LoginProxyUtils.SCOPE + "=" + scope;
    }
}
