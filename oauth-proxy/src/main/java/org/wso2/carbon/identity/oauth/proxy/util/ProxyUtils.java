
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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.Response;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.proxy.bean.ErrorResponse;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;

/**
 * Util class for oauth proxy client module.
 */
public class ProxyUtils {

    private final static Log log = LogFactory.getLog(ProxyUtils.class);

    public static final String CARBON_HOME = "carbon.home";

    public static final String ID_TOKEN = "id_token";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String EXPIRATION = "expires_in";
    public static final String SPA_NAME = "spa_name";

    public static final String PROXY_API = "/";

    public static final String IS_AUTHORIZATION_EP = "/oauth2/authorize";
    public static final String IS_TOKEN_EP = "/oauth2/token";

    public static final String IS_SERVER_EP = "is_server_ep";

    public static final String SECRET_KEY = "secret_key";
    public static final String IV = "iv";

    public static final String CLIENT_ID = "client_id";
    public static final String CLIENT_SECRET = "client_secret";

    public static final String OAUTH_GRANT_TYPE_CODE = "code";
    public static final String SCOPE = "scope.";
    public static final String OPENID_SCOPE = "openid";

    public static final String AUTHENTICATED = "authenticated";
    public static final String AUTHENTICATED_SCOPES = "authenticated_scopes";

    public static final String ID_TOKEN_EXPIRY_TIME = "exp";
    public static final String ID_TOKEN_ISSUED_TIME = "iat";
    public static final int ONE_THOUSAND = 1000;

    private static final String PROXY_ROPERTIES_FILE = "oauth_proxy.properties";
    private static final String OAUTH_PROXY_CONFIG_PATH = "oauth.proxy.property.file.path";
    private static final String SP_CALLBACK_URL_MAPPING = "sp_callback_url_mapping.";
    private static final String SP_CLOGOUT_URL_MAPPING = "sp_logout_url_mapping.";
    private static final String PROXY_CALLBACK_URL = "proxy_callback_url";
    private static final String TIME_SKEW = "time_skew";
    private static final int DEFAULT_TIME_SKEW = 0;

    private static Properties properties = new Properties();

    // Reads the oauth_proxy.properties file.
    // On failure throws RunTimeException to stop the oauth proxy client.
    static {
        FileInputStream fileInputStream = null;
        String configPath = System.getProperty(OAUTH_PROXY_CONFIG_PATH,
                System.getProperty(CARBON_HOME) + File.separator + "repository" + File.separator + "conf");
        try {
            configPath = configPath + File.separator + PROXY_ROPERTIES_FILE;
            fileInputStream = new FileInputStream(new File(configPath));
            properties.load(fileInputStream);
        } catch (FileNotFoundException e) {
            log.error(e);
            throw new RuntimeException(PROXY_ROPERTIES_FILE + " property file not found in " + configPath, e);
        } catch (IOException e) {
            log.error(e);
            throw new RuntimeException(PROXY_ROPERTIES_FILE + " property file reading error from " + configPath, e);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (Exception exx) {
                    log.error("Error occured while closing the file stream :" + exx);
                }
            }
        }
    }

    /**
     * status of the operation.
     */
    public enum OperationStatus {
        SUCCESS, BAD_REQUEST, NOT_FOUND, FORBIDDEN, CREATED, INTERNAL_SERVER_ERROR
    }

    public static String getAuthzEp() {
        return getProperty(IS_SERVER_EP, null) + IS_AUTHORIZATION_EP;
    }

    public static String getTokenEp() {
        return getProperty(IS_SERVER_EP, null) + IS_TOKEN_EP;
    }

    public static String getConsumerKey(String spaName) {
        return getProperty(CLIENT_ID + "." + spaName, getProperty(CLIENT_ID, null));
    }

    public static String getConsumerSecret(String spaName) {
        return getProperty(CLIENT_SECRET + "." + spaName, getProperty(CLIENT_SECRET, null));

    }

    public static String getAuthzGrantType() {
        return OAUTH_GRANT_TYPE_CODE;
    }

    public static String getScope(String spaName) {
        return getProperty(SCOPE + spaName.toLowerCase(), OPENID_SCOPE);

    }

    public static String getSpaCallbackUrl(String spaName) {
        return getProperty(SP_CALLBACK_URL_MAPPING + spaName.toLowerCase(), null);
    }

    public static String getSpaLogoutUrl(String spaName) {
        return getProperty(SP_CLOGOUT_URL_MAPPING + spaName.toLowerCase(), null);
    }

    public static String getCallbackUrl() {
        return getProperty(PROXY_CALLBACK_URL, null);
    }

    /**
     * Retrieve the time_skew property from the oauth_proxy.properties.
     * If not defined default to 0 (DEFAULT_TIME_SKEW).
     * @return time skew
     * @throws OAuthProxyException when time_skew property is not a number.
     */
    public static int getTimeSkew() throws OAuthProxyException {
        String time_skew = getProperty(TIME_SKEW, null);
        if (time_skew != null) {
            try {
                return Integer.parseInt(time_skew);
            } catch (NumberFormatException e) {
                throw new OAuthProxyException(
                        "time_skew property in the oauth_proxy.properties is not a valid number.", e);
            }
        }
        // If the time_skew property is not defined in the oauth_proxy.properties default to 0 time skew.
        return DEFAULT_TIME_SKEW;
    }

    /**
     * Construct the cookie name to store SPA name.
     *
     * @param code appSessionId code
     * @return String SPA_NAME const appended to code
     */
    public static String getSpaNameCookieName(String code) {
        return code + "." + ProxyUtils.SPA_NAME;
    }

    /**
     * Creates the error response to be sent to the calling application, by the API.
     * 
     * @param responseStatus ProxyUtils.OperationStatus
     * @param faultyCode ProxyFaultCodes
     * @param faultyCodeName ProxyFaultCodes.Name
     * @param detail error message
     * @return Response
     */
    public static Response handleErrorResponse(ProxyUtils.OperationStatus responseStatus, String faultyCode,
                                               String faultyCodeName, String detail) {
        Response response;

        String message = faultyCodeName;
        ErrorResponse resp = new ErrorResponse(faultyCode, faultyCodeName, detail);

        switch (responseStatus) {
        case CREATED:
            response = Response.created(URI.create(message)).build();
            break;
        case SUCCESS:
            response = Response.ok().entity(resp).build();
            break;
        case BAD_REQUEST:
            response = Response.status(HttpStatus.SC_BAD_REQUEST).entity(resp).build();
            break;
        case NOT_FOUND:
            response = Response.status(HttpStatus.SC_NOT_FOUND).entity(resp).build();
            break;
        case FORBIDDEN:
            response = Response.status(HttpStatus.SC_UNAUTHORIZED).entity(resp).build();
            break;
        case INTERNAL_SERVER_ERROR:
            response = Response.status(HttpStatus.SC_INTERNAL_SERVER_ERROR).entity(resp).build();
            break;
        default:
            response = Response.noContent().build();
        }
        if (log.isDebugEnabled()) {
            log.debug(resp.toString());
        }
        return response;
    }

    /**
     * Encrypt and base64 encode the given plainText string value.
     *
     * @param plainText string value to be decrypted.
     * @return encrypted string value.
     * @throws OAuthProxyException when configurations are not correct.
     */
    public static String encrypt(String plainText) throws OAuthProxyException {

        String key = properties.getProperty(SECRET_KEY);
        if (key == null) {
            throw new OAuthProxyException("No client secret key is defined in the oauth_proxy.properties " +
                    "configuration file.");
        }

        String initVector = properties.getProperty(IV);
        if (initVector == null) {
            throw new OAuthProxyException("No initialization vector is defined in the oauth_proxy.properties " +
                    "configuration file.");
        }

        IvParameterSpec iv;
        SecretKeySpec skeySpec;
        try {
            iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        } catch (UnsupportedEncodingException e) {
            throw new OAuthProxyException("Initialization vector or client secret key does not support UTF-8 " +
                    "encoding", e);
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            return Base64.encode(encrypted);
        } catch (GeneralSecurityException e) {
            throw new OAuthProxyException("Error occurred while encrypting the plain text", e);
        }
    }

    /**
     * Decrypt the given base64-encoded encrypted Text String.
     *
     * @param encryptedText encryptedText string value.
     * @return decrypted string value.
     * @throws OAuthProxyException when configurations are not correct.
     */
    public static String decrypt(String encryptedText) throws OAuthProxyException {

        String key = properties.getProperty(SECRET_KEY);
        if (key == null) {
            throw new OAuthProxyException("No client secret key is defined in the oauth_proxy.properties " +
                    "configuration file.");
        }

        String initVector = properties.getProperty(IV);
        if (initVector == null) {
            throw new OAuthProxyException("No initialization vector is defined in the oauth_proxy.properties " +
                    "configuration file.");
        }

        IvParameterSpec iv;
        SecretKeySpec skeySpec;
        try {
            iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        } catch (UnsupportedEncodingException e) {
            throw new OAuthProxyException("Initialization vector or client secret key does not support UTF-8 " +
                    "encoding", e);
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decode(encryptedText));
            return new String(original);
        } catch (GeneralSecurityException e) {
            throw new OAuthProxyException("Error occurred while decrypting the encrypted text", e);
        }
    }

    /**
     * Get the loaded properties from the oauth_proxy.properties file.
     *
     * @param key property key.
     * @param defaultValue defaultValue to be sent if no corresponding property value found.
     * @return String property value.
     */
    private static String getProperty(String key, String defaultValue) {
        String propValue = (String) properties.get(key);
        return StringUtils.isNotEmpty(propValue) ? propValue.trim() : defaultValue;
    }
}
