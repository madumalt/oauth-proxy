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

import org.apache.commons.lang.StringUtils;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Unit test class for APIQueryParser class.
 */
public class APIQueryParserTest {
    @Test
    public void testParse() throws Exception {
    }

    @Test
    public void testDecode() throws Exception {
    }

    @DataProvider(name = "queryParams")
    Object[][] queryParams(){
        return new Object[][] {
                {"name:thilina,city:colombo,country:sri lanka", 3},
                {StringUtils.EMPTY, 0}
        };
    }

    @Test(dataProvider="queryParams")
    public void testDecodeQueryParams(String queryParams, int queryParamsMapSize) throws Exception {
        assertEquals(APIQueryParser.decodeQueryParams(queryParams).size(), queryParamsMapSize);
    }

    @DataProvider(name = "apiQueryStrings")
    Object[][] apiQueryString(){
        return new Object[][] {
                {"get \"name:thilina,city:colombot,country:sri lanka\" from https://some.url.com",
                        "name:thilina,city:colombot,country:sri lanka"},
                {"get from https://some.url.com", StringUtils.EMPTY}
        };
    }

    @Test(dataProvider = "apiQueryStrings")
    public void testGetQueryParams(String apiQuery, String result) throws Exception {
        assertEquals(APIQueryParser.getQueryParams(apiQuery), result);
    }

    @Test
    public void testGetHttpVerbMap() throws Exception {
    }

}