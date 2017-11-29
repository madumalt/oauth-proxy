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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.wso2.carbon.identity.oauth.proxy.exceptions.InvalidInputException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OperationFailureExceptions;
import org.wso2.carbon.identity.oauth.proxy.exceptions.ProxyConfigurationException;
import org.wso2.carbon.identity.oauth.proxy.utils.APIProxyUtils;
import org.wso2.carbon.identity.oauth.proxy.utils.LoginProxyUtils;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyFaultCodes;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * This endpoint act as a proxy endpoint for calling back-end APIs on behalf of the SPA.
 * The host mapping for the back-end APIs is retrieved from host-mapping property in the property file.
 * For an E.g https://apple.com/oauth2-proxy/api/{code}/bar?beer-count=3  => https://orange.com/bar?beer-count=3.
 * All the Query Parameters are passed to the back-end APIs as it is.
 *
 */
@Consumes({MediaType.APPLICATION_JSON})
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
     * is received via a cookie whose name is {Spa-Session-Id}.
     * Id for spa session should come as a request header, Spa-Session-Id: {code}
     *
     * @return Response
     */
    // Wildcard path for any path starting with /api/
    @Path("/{var:.*}")
    @GET
    public Response callAPI() {

        // Extract the Spa-Session-Id from the request header.
        String spaSessionId = getSpaSessionId(context.getHttpServletRequest());

        // Application Session Id code cannot be empty.
        if (StringUtils.isEmpty(spaSessionId)) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST, ProxyFaultCodes.ERROR_002,
                    "The value of the Spa-Session-Id cannot be found in the request header.");
        }

        try {
            String forwardRequestUrl = buildForwardRequestUrl(context.getHttpServletRequest(), spaSessionId);
            String accessToken = APIProxyUtils.getAccessToken(context.getHttpServletRequest(), spaSessionId);

            // Respond with an error when no access_token is found.
            if (StringUtils.isEmpty(accessToken)) {
                return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.FORBIDDEN, ProxyFaultCodes.ERROR_011,
                        "No accessToken found in the cookie holding the jwt.");
            }

            return APIProxyUtils.doBearerAuthorizedGetCall(forwardRequestUrl, accessToken);
        } catch (InvalidInputException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.BAD_REQUEST,
                    ProxyFaultCodes.ERROR_002, e.getMessage());
        } catch (OperationFailureExceptions | ProxyConfigurationException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR,
                    ProxyFaultCodes.ERROR_003, e.getMessage());
        }
    }

    /**
     * Build the Http request pointing to backend api.
     *
     * @param request        received ServletRequest
     * @param appSessionCode code id for application session
     * @return String forwardRequestUrl
     * @throws OAuthProxyException when host mapping not found
     */
    private String buildForwardRequestUrl(HttpServletRequest request, String appSessionCode)
            throws ProxyConfigurationException {
        String host = request.getHeader(ProxyUtils.HOST_REQUEST_HEADER);
        boolean isSecure = request.isSecure();
        String requestContextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        String queryString = request.getQueryString();

        // Set protocol of the absolute forward Uri.
        String protocol = isSecure ? ProxyUtils.HTTPS : ProxyUtils.HTTP;
        StringBuilder absoluteForwardUri = new StringBuilder(protocol);

        // Retrieve the application name from the <code>.spa_name cookie.
        String spaName = ProxyUtils.getCookievalue(request.getCookies(), LoginProxyUtils.getSpaNameCookieName
                (appSessionCode));

        // Throw OAuthProxyException when no host-mapping found.
        String mappedHost = APIProxyUtils.getMappedHost(spaName, host);
        if (StringUtils.isEmpty(mappedHost)) {
            throw new ProxyConfigurationException("No host name mapping for: " + spaName + "." + host
                    + " can be found in the configurations.");
        }

        // Append the mapped host to absolute forward Uri.
        absoluteForwardUri.append(mappedHost);

        // Remove api proxy context path corresponding to the application session to get the forward Uri.
        String forwardUri = requestUri.replace(APIProxyUtils.getApiProxyContextPath(requestContextPath),
                StringUtils.EMPTY);
        absoluteForwardUri.append(forwardUri);

        // Append query string to the absolute forward Uri.
        absoluteForwardUri.append(ProxyUtils.URI_QUERY_PARAMS_SEPARATOR);
        absoluteForwardUri.append(queryString);

        return absoluteForwardUri.toString();
    }

    /**
     * Extract the Spa-Seesion-Id from the request header.
     *
     * @param request HttpServletRequest received from the client
     * @return Spa-Session-Id
     */
    private String getSpaSessionId(HttpServletRequest request) {
        return request.getHeader(APIProxyUtils.SPA_SESSION_ID_HEADER);
    }
}
