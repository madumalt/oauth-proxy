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

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;
import org.wso2.carbon.identity.oauth.proxy.utils.APIProxyUtils;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyFaultCodes;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

/**
 * This endpoint act as a proxy endpoint for calling back-end APIs on behalf of the SPA.
 * The host mapping for the back-end APIs is retrieved from a host-mapping property file.
 * For an E.g https://apple.com/oauth2-prxoy/api/{code}/bar?beer-count=3  => https://orange.com/bar?beer-count=3.
 * All the Query Parameters are passed to the back-end APIs as it is.
 *
 * @Path /api
 */
@Consumes({ MediaType.APPLICATION_JSON })
@Produces(MediaType.APPLICATION_JSON)
public class APIProxy {

    private final static Log log = LogFactory.getLog(APIProxy.class);

    // Keeps track of HttpServletRequest and HttpServletResponse
    @Context
    private MessageContext context;


    /**
     * This method act as an api gateway.
     * Invoke the intended backend api, and returns the response.
     * Adds the access_token in Authorization Bearer Header when invoking the intended api.
     * An Encrypted jwt comprised of acces_token, refresh_token, and payload of id_token
     * is received via a cookie whose name is {code}.
     *
     * @param code code id for application session
     * @return Response
     */
    // Wildcard path for any path starting with /api/{code}
    @Path("{code}/{var:.*}")
    @GET
    public Response callAPI(@PathParam("code") String code) {

        // Application Session Id code cannot be empty.
        if (StringUtils.isEmpty(code)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.errorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002, "The value of the code cannot be null.");
        }

        HttpClient httpClient = new HttpClient();
        HttpMethod httpMethod;
        try {
            httpMethod = buildForwardRequest(context.getHttpServletRequest(), code);

            String access_token = getAccessToken(context.getHttpServletRequest(), code);
            // Respond with an error when no access_token is found.
            if (StringUtils.isEmpty(access_token)) {
                return ProxyUtils.handleErrorResponse(ProxyUtils.errorStatus.FORBIDDEN, ProxyFaultCodes.ERROR_011, "No access_token found in the cookie jwt.");
            }

            // Set Authorization header.
            Header authorizationHeader = new Header(APIProxyUtils.AUTHORIZATION_HEADER,
                    String.format(APIProxyUtils.AUTHORIZATION_BEARER, access_token));
            httpMethod.addRequestHeader(authorizationHeader);

            try {
                // Forward the api request.
                int statusCode = httpClient.executeMethod(httpMethod);

                // TODO what else should be there in the response?
                // Build the response from the response received by invoking the api request.
                Response response = Response.status(statusCode).entity(httpMethod.getResponseBodyAsString()).build();
                return response;
            } catch (IOException e) {
                return ProxyUtils.handleErrorResponse(ProxyUtils.errorStatus.INTERNAL_SERVER_ERROR, ProxyFaultCodes
                        .ERROR_003, "Error while forwarding the request: " + httpMethod.getPath());
            } finally {
                if (httpMethod != null) {
                    httpMethod.releaseConnection();
                }
            }
        } catch (OAuthProxyException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.errorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }
    }

    /**
     * Build the Http request pointing to backend api.
     *
     * @param request received ServletRequest
     * @param appSessionCode code id for application session
     * @return HttpMethod
     * @throws OAuthProxyException when host mapping not found
     */
    private HttpMethod buildForwardRequest(HttpServletRequest request, String appSessionCode) throws
            OAuthProxyException {
        String host = request.getHeader(APIProxyUtils.HOST_REQUEST_HEADER);
        boolean isSecure = request.isSecure();
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        String queryString = request.getQueryString();

        // Set protocol of the absolute forward Uri.
        String protocol = isSecure ? APIProxyUtils.HTTPS : APIProxyUtils.HTTP;
        StringBuilder absoluteForwardUri = new StringBuilder(protocol);

        // Throw OAuthProxyException when no host-mapping found.
        if (StringUtils.isEmpty(APIProxyUtils.getHostMapping().get(host))) {
            throw new OAuthProxyException("No host name mapping for: " + host + "found in the configurations.");
        }

        // Append the mapped host to absolute forward Uri.
        absoluteForwardUri.append(APIProxyUtils.getHostMapping().get(host));

        // Remove api proxy context path corresponding to the application session to get the forward Uri.
        String forwardUri = requestUri.replace(APIProxyUtils.getApiProxyContextPath(contextPath, appSessionCode), StringUtils.EMPTY);
        absoluteForwardUri.append(forwardUri);

        // Append query string to the absolute forward Uri.
        absoluteForwardUri.append(APIProxyUtils.URI_QUERY_PARAMS_SEPARATOR);
        absoluteForwardUri.append(queryString);

        return new GetMethod(absoluteForwardUri.toString());
    }

    /**
     * Extract the access_token from the corresponding cookie in the request.
     *
     * @param request HttpServletRequest received from the client
     * @param appSeesionCode  identification code for the application session
     * @return String access_token
     * @throws OAuthProxyException
     */
    private String getAccessToken(HttpServletRequest request, String appSeesionCode) throws OAuthProxyException {
        try {
            JSONObject decryptedJwt = ProxyUtils.getDecryptedJwt(request, appSeesionCode);
            return decryptedJwt.getString(ProxyUtils.ACCESS_TOKEN);
        } catch (JSONException e) {
            throw new OAuthProxyException(
                    "Error while retrieving " + ProxyUtils.ACCESS_TOKEN + "from jwt JSONObject.", e);
        }
    }
}
