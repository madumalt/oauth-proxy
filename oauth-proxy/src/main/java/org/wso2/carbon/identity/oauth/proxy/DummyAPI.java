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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.MessageContext;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyFaultCodes;
import org.wso2.carbon.identity.oauth.proxy.utils.ProxyUtils;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

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
        // TODO validate access token against the IS.
        JSONObject json = new JSONObject();
        try {
            json.put("dummy API", name);
            return Response.ok().entity(json.toString()).build();
        } catch (JSONException e) {
            return ProxyUtils.handleErrorResponse(ProxyUtils.ErrorStatus.INTERNAL_SERVER_ERROR, ProxyFaultCodes
                    .ERROR_003, "Error while creating json output");
        }
    }
}
