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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.utils.LoginProxyUtils;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyFaultCodes;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyUtils;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

/**
 * Dummy API for demonstration purpose of the APIProxy. Here all APIs will expect Bearer token at the
 * Authorization Header. Bearer token will be checked against the Authorization server before issuing
 * the requested resources.
 */
@Consumes({ MediaType.APPLICATION_JSON })
@Produces(MediaType.APPLICATION_JSON)
public class DummyAPI {

    private final static Log log = LogFactory.getLog(DummyAPI.class);

    // keeps track of HttpServletRequest and HttpServletResponse
    @Context
    private MessageContext context;

    @Path("secured-resource")
    @GET
    public Response callAPI(@QueryParam("resource-name") String name) {

        /**
         * NOTE: This endpoint is implemented only for demonstration purposes.
         */

        HttpServletRequest request = context.getHttpServletRequest();
        String authHeader = request.getHeader(ProxyUtils.AUTHORIZATION_HEADER);

        if (authHeader == null) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.FORBIDDEN, ProxyFaultCodes
                    .ERROR_011, "No Authorization header is found.");
        }

        String[] authHeaderParts = StringUtils.split(authHeader);
        if (authHeaderParts == null || authHeaderParts.length != 2) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.FORBIDDEN, ProxyFaultCodes
                    .ERROR_011, "No access token is found in the Authorization header.");
        }

        String accessToken = authHeaderParts[1];

        // Build POST request with the given url.
        PostMethod httpPost = new PostMethod(ProxyUtils.getProperty(LoginProxyUtils.IS_SERVER_EP) +
                "/oauth2/introspect");

        // Set Authorization Basic header.
        Header authorizationHeader = new Header(ProxyUtils.AUTHORIZATION_HEADER,
                String.format("Basic %s", Base64.encodeBase64URLSafeString("admin:admin".getBytes())));
        httpPost.addRequestHeader(authorizationHeader);
        // Set token to be validated.
        NameValuePair[] data = {new NameValuePair("token", accessToken)};
        httpPost.setRequestBody(data);

        HttpClient httpClient = new HttpClient();
        try {
            // Call the introspection endpoint.
            int statusCode = httpClient.executeMethod(httpPost);
            // Retrieve the response from the introspection endpoint
            String responseString = httpPost.getResponseBodyAsString();
            JSONObject responseJson = new JSONObject(responseString);

            if(responseJson.has("active")){
                return buildJsonResponse(name, responseJson.getBoolean("active"), responseString);
            } else {
                return buildJsonResponse(name, false, responseString);
            }
        } catch (IOException | JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR, ProxyFaultCodes
                    .ERROR_003, "Error While obtaining introspection response.");
        } finally {
            if (httpPost != null) {
                httpPost.releaseConnection();
            }
        }
    }

    private Response buildJsonResponse(String resourceName, boolean successful, String introspecResponse) {
        JSONObject json = new JSONObject();
        try {
            json.put("resource-name", resourceName);
            json.put("successful", successful);
            json.put("token validation", introspecResponse);
            return Response.ok().entity(json.toString()).build();
        } catch (JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR, ProxyFaultCodes
                    .ERROR_003, "Error while creating json output");
        }
    }
}
