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

package org.wso2.carbon.identity.oauth.proxy.api.query.parser;

import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.oauth.proxy.api.query.parser.exceptions.APIQueryParserException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser class for @QueryParam("query") for APIProxy.
 */
// TODO only get queries are supported.
// TODO refactor the class.
public class APIQueryParser {

    public static HttpMethod parse(String apiQuery) throws APIQueryParserException {

        APIRequestBean apiRequestBean = decode(apiQuery);

        switch(apiRequestBean.getHttpVerb()){
            case GET:
                return createGetRequest(apiRequestBean);
            default:
                return null;
        }
    }

    public static GetMethod createGetRequest(APIRequestBean apiRequestBean) {
        GetMethod getMethod = new GetMethod(apiRequestBean.getApiUrl());
        getMethod.setQueryString(getQueryParamsNameValuePairs(apiRequestBean.getQueryParams()));
        return getMethod;
    }

    public static NameValuePair[] getQueryParamsNameValuePairs(Map<String, String> queryParams) {
        NameValuePair[] nameValuePairs = new NameValuePair[queryParams.size()];
        int index = 0;
        for (Map.Entry<String, String> entry : queryParams.entrySet()){
            nameValuePairs[index] = new NameValuePair(entry.getKey(), entry.getValue());
            index++;
        }
        return nameValuePairs;
    }

    public static APIRequestBean decode(String apiQuery) throws APIQueryParserException {
        APIRequestBean apiRequestBean = new APIRequestBean();

        // Set query params.
        String queryParams = getQueryParams(apiQuery);
        apiRequestBean.setQueryParams(decodeQueryParams(queryParams));

        // TODO create a const for "from"
        // TODO refactor this
        String[] verbNUrl = apiQuery.replace(queryParams, "").replace("\"", "").replace("from", "").split(" +");

        if (verbNUrl.length != 2) {
            throw new APIQueryParserException("APIQuery: " + apiQuery + " is not in correct format");
        }

        // Set HttpVerb.
        HttpVerb verb = getHttpVerbMap().get(verbNUrl[0].toLowerCase());
        if (verb == null) {
            throw new APIQueryParserException("Http verb in the API Query: " + apiQuery + " cannot be null.");
        }
        apiRequestBean.setHttpVerb(verb);

        // Set API Url.
        String apiUrl = verbNUrl[1];
        if (StringUtils.isBlank(apiUrl)) {
            throw new APIQueryParserException("API Url in the API Query: " + apiQuery + " cannot be null.");
        }
        apiRequestBean.setApiUrl(apiUrl);

        return apiRequestBean;
    }

    public static Map<String, String> decodeQueryParams(String queryParams) throws APIQueryParserException {
        if(StringUtils.isBlank(queryParams)){
            return Collections.emptyMap();
        }

        Map<String, String> queryParamsMap = new HashMap<>();

        //TODO create constant for these delimiters
        String queryParamsSeparator = ",";
        String queryParamSeparator = ":";
        String[] qParams = queryParams.split(queryParamsSeparator);
        for (String qParam : qParams){
            String[] qParamValues = qParam.split(queryParamSeparator);
            if (qParamValues.length != 2) {
                throw new APIQueryParserException("Query parameter: " + qParam + " in the APIQuery should have 2 " +
                        "values separated by: " + queryParamSeparator);
            }
            queryParamsMap.put(qParamValues[0], qParamValues[1]);
        }

        return queryParamsMap;
    }

    public static String getQueryParams(String apiQuery) throws APIQueryParserException {

        // Regex for extracting the substring covered with double quotes.
        // [^\"] means any character except "
        // e.g. get "name=thilina&city=colombot&country=sri lanka" from https://some.url.com
        // =>  "name=thilina&city=colombot&country=sri lanka"
        // TODO create constants for this regex.
        String queryParmRegex = "\"([^\"]*)\"";
        Pattern queryParamPattern = Pattern.compile(queryParmRegex);
        Matcher matcher = queryParamPattern.matcher(apiQuery);

        int matchCount = 0;
        String queryParams = StringUtils.EMPTY;
        while (matcher.find()){
            queryParams = matcher.group();
            matchCount++;
            if (matchCount > 1) {
                throw new APIQueryParserException("Wrong query param format in the apiQuery: " + apiQuery + ". Cannot "
                        + "have more than one double quoted values.");
            }
        }

        // Remove quotes.
        return queryParams.replace("\"", "");
    }

    public static class APIRequestBean {
        private HttpVerb httpVerb;
        private Map<String, String> queryParams;
        private String apiUrl;

        public HttpVerb getHttpVerb() {
            return httpVerb;
        }

        public void setHttpVerb(HttpVerb httpVerb) {
            this.httpVerb = httpVerb;
        }

        public Map<String, String> getQueryParams() {
            return queryParams;
        }

        public void setQueryParams(Map<String, String> queryParams) {
            this.queryParams = queryParams;
        }

        public String getApiUrl() {
            return apiUrl;
        }

        public void setApiUrl(String apiUrl) {
            this.apiUrl = apiUrl;
        }
    }

    // TODO only get is supported
    public enum HttpVerb {
        GET("get"),
        POST("post"),
        PUT("put"),
        DELETE("delete");

        private String value;
        HttpVerb(String value){
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    public static Map<String, HttpVerb> getHttpVerbMap(){
        Map<String, HttpVerb> httpVerbMap = new HashMap<>();
        for(HttpVerb httpVerb : HttpVerb.values()){
            httpVerbMap.put(httpVerb.getValue(), httpVerb);
        }
        return httpVerbMap;
    }
}
