
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

package org.wso2.carbon.identity.oauth.proxy.util;

/**
 * 
 */
public class ProxyFaultCodes {

    // user already in the system.
    public static final String ERROR_001 = "ERROR_001";
    // invalid inputs
    public static final String ERROR_002 = "ERROR_002";
    // internal server error
    public static final String ERROR_003 = "ERROR_003";
    // service provider not found
    public static final String ERROR_004 = "ERROR_004";
    // authentication failure
    public static final String ERROR_010 = "ERROR_010";

    public static class Name {
        public static final String INVALID_INPUTS = "Invalid inputs";
        public static final String SERVICE_PROVIDER_DOES_NOT_EXIST = "Service provider does not exist";
        public static final String INTERNAL_SERVER_ERROR = "Internal server error";
        public static final String NO_DATA_FOUND = "No data found";
        public static final String OPERATION_SUCCESSFUL = "Operation successful";
        public static final String AUTHENTICATION_FAILED = "Authentication failed";
        public static final String AUTHORIZATION_FAILED = "Authorization failed";
    }

}
