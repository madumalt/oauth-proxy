
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
import java.util.regex.Pattern;

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

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthClientResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;
import org.wso2.carbon.identity.oauth.proxy.util.ProxyFaultCodes;
import org.wso2.carbon.identity.oauth.proxy.util.ProxyUtils;

/**
 * this endpoint acts a proxy end-point single page applications(SPA). to authenticate a user, the SPA must do a GET to
 * the /login end-point with spaName and code parameters. spaName is a unique identifier for each SPA, and the proxy
 * application should be aware of that identifier.the proxy end-point uses the spaName later to load the callback URL
 * corresponding to the SPA. the code is a random generated number by the SPA. SPA should guarantee its randomness. each
 * times the SPA gets rendered on the browser it has to generate the code.spas should not uses statically configured
 * code values.
 * 
 */
@Path(ProxyUtils.PROXY_API)
@Consumes({ MediaType.APPLICATION_JSON })
@Produces(MediaType.APPLICATION_JSON)
public class LoginProxy {

    private final static Log log = LogFactory.getLog(LoginProxy.class);

    // keeps track of HttpServletRequest and HttpServletResponse
    @Context
    private MessageContext context;

    /**
     * this is the first API, the SPA should call to initiate user authentication. this method will redirect the user to
     * the identity server's OAuth 2.0 authorization endpoint.the value of the code parameter will be written to a
     * cookie, so it can be accessed when get redirected back from the identity server, after user authentication.
     * 
     * @param spaName paName is a unique identifier for each SPA, and the proxy application should be aware of that
     *            identifier.the proxy end-point uses the spaName later to load the callback URL corresponding to the
     *            SPA.
     * @param code each times the SPA gets rendered on the browser it has to generate the code.spas should not uses
     *            statically configured code values.
     * @return Response
     */
    @Path("login")
    @GET
    public Response getAuthzCode(@QueryParam("spaName") String spaName, @QueryParam("code") String code) {

        if (spaName == null || spaName.isEmpty()) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "The value of the spaName cannot be null.");
        }

        if (code == null || code.isEmpty()) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "The value of the code cannot be null.");
        }

        HttpServletResponse resp = context.getHttpServletResponse();

        // loads the client key corresponding to the SPA. you do not need to have SPA specific consumer keys, rather can
        // use one client key for all the SPAs. you get the consumer key from the identity server, at the time you
        // register the service provider, and configure it in oauth_proxy.properties file.
        String consumerKey = ProxyUtils.getConsumerKey(spaName);
        // this is the OpenID 2.0 authorization end-point of the identity server.
        String authzEndpoint = ProxyUtils.getAuthzEp();
        // get the grant type. the proxy works only with the authorization code grant type.
        String authzGrantType = ProxyUtils.getAuthzGrantType();
        // get the scope associated with the SPA. each SPA can define its own scopes in the oauth_proxy.properties file,
        // but in each case OPENID is used as a mandatory scope value.
        String scope = ProxyUtils.getScope(spaName);
        // load the callback URL of the proxy. there is only one callback URL. even when you create multiple service
        // providers in identity server to get multiple client key/client secret pairs, the callback URL would be the
        // same.
        String callbackUrl = ProxyUtils.getCallbackUrl();

        OAuthClientRequest authzRequest = null;

        try {
            // create a cookie under the proxy domain having code as the key and spaName as the value.
            Cookie cookie = new Cookie(ProxyUtils.getSpaNameCookieName(code), spaName);
            // this cookie is only accessible by HTTPS transport.
            cookie.setSecure(true);
            // add cookie to the response.
            resp.addCookie(cookie);

            // create the OAuth 2.0 request with all necessary parameters. the code passed by the SPA is set as the
            // state - so the identity server will return it back with the OAuth response. we use the value of the code
            // (or the state here) to retrieve the cookie later. this is done in a way to make this proxy application
            // state-less.
            authzRequest = OAuthClientRequest.authorizationLocation(authzEndpoint).setClientId(consumerKey)
                    .setRedirectURI(callbackUrl).setResponseType(authzGrantType).setScope(scope).setState(code)
                    .buildQueryMessage();
        } catch (OAuthSystemException e) {
            log.error(e);
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }

        try {
            // redirects the user to the identity server's authorization end-point.
            resp.sendRedirect(authzRequest.getLocationUri());
            // Once redirection is successful no need to return a response thus returning null.
            return null;
        } catch (IOException e) {
            log.error(e);
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }

    }

    /**
     * this is the method, which gets fired when the identity server returns back the authorization code, after
     * authenticating the user. in addition to the authorization code, the response from the identity server must also
     * include the state parameter, which contains the value we set when we initiate the authorization grant.
     * 
     * @param code the authorization code generated by the identity server. the proxy application will exchange this
     *            token to get an access token from the identity server.
     * @param state this is the same value we set as state, when we initiate the authorization grant request to the
     *            identity server.
     * @return Response
     */
    @Path("callback")
    @GET
    public Response handleCallback(@QueryParam("code") String code, @QueryParam("state") String state) {

        if (code == null || code.isEmpty()) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "The value of the code cannot be null.");
        }

        if (state == null || state.isEmpty()) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "The value of the state cannot be null.");
        }

        HttpServletResponse resp = context.getHttpServletResponse();
        HttpServletRequest req = context.getHttpServletRequest();
        Cookie[] cookies = req.getCookies();
        // try to load the cookie corresponding to the value of the state.
        String spaName = getCookievalue(cookies, ProxyUtils.getSpaNameCookieName(state));

        if (StringUtils.isEmpty(spaName)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "No valid cookie found.");
        }

        // loads the client key corresponding to the SPA. you do not need to have SPA specific consumer keys, rather
        // can use one client key for all the SPAs. you get the consumer key from the identity server, at the time you
        // register the service provider, and configure it in oauth_proxy.properties file.
        String consumerKey = ProxyUtils.getConsumerKey(spaName);
        // loads the client secret corresponding to the SPA. you do not need to have SPA specific client secret, rather
        // can use one client secret for all the SPAs. you get the client secret from the identity server, at the time
        // you register the service provider, and configure it in oauth_proxy.properties file.
        String consumerSecret = ProxyUtils.getConsumerSecret(spaName);
        // this is the OAuth 2.0 token end-point of the identity server.
        String tokenEndpoint = ProxyUtils.getTokenEp();
        // load the callback URL of the proxy. there is only one callback URL. even when you create multiple service
        // providers in identity server to get multiple client key/client secret pairs, the callback URL would be the
        // same.
        String callbackUrl = ProxyUtils.getCallbackUrl();

        OAuthClientRequest accessRequest = null;

        try {
            // create an OAuth 2.0 token request.
            accessRequest = OAuthClientRequest.tokenLocation(tokenEndpoint).setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(consumerKey).setClientSecret(consumerSecret).setRedirectURI(callbackUrl).setCode(code)
                    .buildBodyMessage();
        } catch (OAuthSystemException e) {
            log.error(e);
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }

        // create an OAuth 2.0 client that uses custom HTTP client under the hood
        OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
        OAuthClientResponse oAuthResponse = null;

        try {
            // talk to the OAuth token end-point of identity server to get the OAuth access token, refresh token and id
            // token.
            oAuthResponse = oAuthClient.accessToken(accessRequest);
        } catch (OAuthSystemException e) {
            log.error(e);
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        } catch (OAuthProblemException e) {
            log.error(e);
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }

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
        } catch (JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }

        try {
            // encrypt the JSON message.
            String encryptedCookieValue = ProxyUtils.encrypt(json.toString());
            // create a cookie under the proxy domain with the encrypted message. cookie name is set to the value of the
            // code, initially passed by the SPA.
            Cookie cookie = new Cookie(state, encryptedCookieValue);
            // the cookie is only accessible by the HTTPS transport.
            cookie.setSecure(true);
            // add cookie to the response.
            resp.addCookie(cookie);
            // get the SPA callback URL. each SPA has its own callback URL, which is defined in the
            // oauth_proxy.properties file
            resp.sendRedirect(ProxyUtils.getSpaCallbackUrl(spaName));
            // Once redirection is successful no need to return a response thus returning null.
            return null;
        } catch (OAuthProxyException | IOException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * clears all the cookies corresponding to the spa.
     * 
     * @param code appSessionId code
     * @return Response
     */
    @Path("logout")
    @GET
    public Response logout(@QueryParam("code") String code) {

        if (code == null || code.isEmpty()) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "The value of the code cannot be null.");
        }

        HttpServletRequest req = context.getHttpServletRequest();
        HttpServletResponse resp = context.getHttpServletResponse();

        Cookie[] cookies = req.getCookies();
        String spaName = getCookievalue(cookies, ProxyUtils.getSpaNameCookieName(code));

        clearCookies(resp, cookies, code);

        if (spaName == null) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_004, ProxyFaultCodes.Name.SERVICE_PROVIDER_DOES_NOT_EXIST,
                    "No spa found for corresponding to the provided code");
        }

        try {
            resp.sendRedirect(ProxyUtils.getSpaLogoutUrl(spaName));
            return null;
        } catch (IOException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * this is invoked by the SPA to get user information. the proxy will decrypt the cookie (having the value of the
     * code parameter is its name) to extract out the user information and will send back a JSON response to the SPA.
     * 
     * @param code this should be the same code, which is used by the SPA, to talk to the /login end-point previously.
     * @return Response
     */
    @Path("users")
    @GET
    public Response getUserInfo(@QueryParam("code") String code) {

        if (code == null || code.isEmpty()) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "The value of the code cannot be null.");
        }

        HttpServletRequest req = context.getHttpServletRequest();
        Cookie[] cookies = req.getCookies();
        // try to load the cookie corresponding to the value of the code.
        String encryptedCookieValue = getCookievalue(cookies, code);

        if (StringUtils.isEmpty(encryptedCookieValue)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "No valid cookie found.");
        }

        JSONObject json;
        try {
            // decrypted ciphertext will return back a JSON.
            String plainTextCookieValue = ProxyUtils.decrypt(encryptedCookieValue);
            json = new JSONObject(plainTextCookieValue);
            // loads the user info from the JSON object.
            String userInfo = json.getString(ProxyUtils.ID_TOKEN);
            // send back the base64url-decode user info response to the SPA.
            return Response.ok().entity(base64UrlDecode(userInfo)).build();
        } catch (OAuthProxyException | JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * This will be invoked by the SPA to check whether the user is authenticated.
     * If the id_token expiry time is higher than the current time will send {authenticated: true}.
     * Otherwise will send {authenticated: false}.
     *
     * @param code this should be the same code, which is used by the SPA, to talk to the /login end-point initially.
     * @return Response {authenticated: true/false}
     */
    @Path("authenticated")
    @GET
    public Response validateUserAuthentication(@QueryParam("code") String code) {

        // AppSessionId code cannot be null.
        if (code == null || code.isEmpty()) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    ProxyFaultCodes.Name.INVALID_INPUTS, "The value of the code cannot be null.");
        }

        HttpServletRequest req = context.getHttpServletRequest();
        Cookie[] cookies = req.getCookies();
        // try to load the cookie corresponding to the value of the code.
        String encryptedCookieValue = getCookievalue(cookies, code);

        // No cookie corresponding to the code means, not authenticated.
        if (StringUtils.isEmpty(encryptedCookieValue)) {
            return buildAuthenticatedResponse(false);
        }

        // Decrypt the corresponding cookie and validate the access-token against IS introspection endpoint.
        try{
            JSONObject cookieValue = new JSONObject(ProxyUtils.decrypt(encryptedCookieValue));

            String accessToken = cookieValue.getString(ProxyUtils.ACCESS_TOKEN);
            String idToken = cookieValue.getString(ProxyUtils.ID_TOKEN);

            if (StringUtils.isNotEmpty(accessToken) && StringUtils.isNotEmpty(idToken)){
                JSONObject idTokenInfo = new JSONObject(base64UrlDecode(idToken));
                // Since id_token expiry time and issued time are in seconds need to get current time also in seconds.
                long currentTime = Calendar.getInstance().getTimeInMillis() / ProxyUtils.ONE_THOUSAND;
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
        } catch (OAuthProxyException | JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * Gives the corresponding cookie value for the given cookieName.
     * @param cookies cookies received along the request.
     * @param cookieName cookieName.
     * @return cookie value, can be null.
     */
    private static String getCookievalue(Cookie[] cookies, String cookieName) {
        Cookie cookie = getCookie(cookies, cookieName);
        return cookie != null ? cookie.getValue() : StringUtils.EMPTY;
    }

    /**
     * Gives the corresponding cookie for the given cookieName.
     *
     * @param cookies cookies received along the request.
     * @param cookieName cookieName.
     * @return cookie can be null.
     */
    private static Cookie getCookie(Cookie[] cookies, String cookieName) {
        if (cookies != null){
            for(Cookie cookie: cookies) {
                if(cookie.getName().equals(cookieName)) {
                    return cookie;
                }
            }
        }
        return null;
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
                        || cookie.getName().equals(ProxyUtils.getSpaNameCookieName(code))) {
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
            responseJson.put(ProxyUtils.AUTHENTICATED, isAuthenticated);
            return Response.ok(responseJson.toString(), MediaType.APPLICATION_JSON_TYPE).build();
        } catch (JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.OperationStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, ProxyFaultCodes.Name.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    /**
     * base64url-decode the provided text.
     * 
     * @param base64UrlEncodedStr encoded value.
     * @return String base-64 Url-decoded value.
     */
    private static String base64UrlDecode(String base64UrlEncodedStr) {
        return new String(Base64.decodeBase64(base64UrlEncodedStr.getBytes()));
    }
}
