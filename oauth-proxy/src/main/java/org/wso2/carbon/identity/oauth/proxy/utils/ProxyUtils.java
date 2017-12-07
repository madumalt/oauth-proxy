
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

package org.wso2.carbon.identity.oauth.proxy.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.wso2.carbon.identity.oauth.proxy.bean.ErrorResponse;
import org.wso2.carbon.identity.oauth.proxy.exceptions.InvalidInputException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OAuthProxyException;
import org.wso2.carbon.identity.oauth.proxy.exceptions.OperationFailureExceptions;
import org.wso2.carbon.identity.oauth.proxy.exceptions.ProxyConfigurationException;

/**
 * Util class for oauth proxy client module.
 */
public class ProxyUtils {
    private final static Log log = LogFactory.getLog(ProxyUtils.class);

    public static final String API_ENDPOINT = "/api";

    public static final String HTTPS = "https://";
    public static final String HTTP = "http://";
    public static final String HOST_REQUEST_HEADER = "host";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTHORIZATION_BEARER = "Bearer %s";
    public static final String URI_QUERY_PARAMS_SEPARATOR = "?";

    public static final String ID_TOKEN = "id_token";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String EXPIRATION = "expires_in";
    public static final String SPA_NAME = "spa_name";

    public static final String SECRET_KEY = "secret_key";
    public static final String IV = "iv";

    public static final String ID_TOKEN_EXPIRY_TIME = "exp";
    public static final String ID_TOKEN_ISSUED_TIME = "iat";
    public static final int MILLIS_TO_SECONDS_CONVERT_FACTOR = 1000;

    private static final String PROXY_PROPERTIES_FILE = "proxy.properties";

    private static Properties properties = null;

    /**
     * base64url-decode the provided text.
     *
     * @param base64UrlEncodedStr encoded value.
     * @return String base-64 Url-decoded value.
     */
    public static String base64UrlDecode(String base64UrlEncodedStr) {
        return new String(org.apache.commons.codec.binary.Base64.decodeBase64(base64UrlEncodedStr.getBytes()));
    }

    /**
     * Gives the corresponding cookie value for the given cookieName.
     * @param cookies cookies received along the request.
     * @param cookieName cookieName.
     * @return cookie value, can be null.
     */
    public static String getCookievalue(Cookie[] cookies, String cookieName) {
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
    public static Cookie getCookie(Cookie[] cookies, String cookieName) {
        if (cookies != null) {
            for (Cookie cookie: cookies) {
                if (cookie.getName().equals(cookieName)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * Gives the base64 decoded, decrypted jwt as a JSONObject.
     *
     * @param request HttpServletRequest from the client
     * @param appSeesionCode identification code for the application session
     * @return JSONObject decrypted jwt
     * @throws OAuthProxyException
     */
    public static JSONObject getDecryptedJwt(HttpServletRequest request, String appSeesionCode)
            throws InvalidInputException, ProxyConfigurationException, OperationFailureExceptions {

        Cookie[] cookies = request.getCookies();
        // try to load the cookie corresponding to the value of the appSeesionCode.
        String encryptedjwt = ProxyUtils.getCookievalue(cookies, appSeesionCode);

        if (StringUtils.isEmpty(encryptedjwt)) {
            throw new InvalidInputException("No valid cookie holding the token data is found.");
        }

        try {
            return new JSONObject(ProxyUtils.decrypt(encryptedjwt));
        } catch (JSONException e) {
            throw new OperationFailureExceptions("Error while creating a JSONObject from decrypted jwt.", e);
        }
    }

    /**
     * Error status of the api operations.
     */
    public enum ErrorStatus {
        BAD_REQUEST, NOT_FOUND, FORBIDDEN, INTERNAL_SERVER_ERROR
    }

    /**
     * Creates the error response to be sent to the calling application, by the API.
     * 
     * @param responseStatus ProxyUtils.ErrorStatus
     * @param faultyCode ProxyFaultCodes
     * @param detail error message
     * @return Response
     */
    public static Response handleErrorResponse(ErrorStatus responseStatus, ProxyFaultCodes faultyCode, String detail) {
        ErrorResponse resp = new ErrorResponse(faultyCode.name(), faultyCode.getMessage(), detail);
        switch (responseStatus) {
        case BAD_REQUEST:
            return Response.status(HttpStatus.SC_BAD_REQUEST).entity(resp).build();
        case NOT_FOUND:
            return Response.status(HttpStatus.SC_NOT_FOUND).entity(resp).build();
        case FORBIDDEN:
            return Response.status(HttpStatus.SC_UNAUTHORIZED).entity(resp).build();
        case INTERNAL_SERVER_ERROR:
            return Response.status(HttpStatus.SC_INTERNAL_SERVER_ERROR).entity(resp).build();
        default:
            return Response.noContent().build();
        }
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
    public static String decrypt(String encryptedText) throws ProxyConfigurationException, OperationFailureExceptions {

        String key = properties.getProperty(SECRET_KEY);
        if (key == null) {
            throw new ProxyConfigurationException("No client secret key is defined in the oauth_proxy.properties " +
                    "configuration file.");
        }

        String initVector = properties.getProperty(IV);
        if (initVector == null) {
            throw new ProxyConfigurationException("No initialization vector is defined in the oauth_proxy.properties " +
                    "configuration file.");
        }

        IvParameterSpec iv;
        SecretKeySpec skeySpec;
        try {
            iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        } catch (UnsupportedEncodingException e) {
            throw new ProxyConfigurationException("Initialization vector or client secret key does not support UTF-8 " +
                    "encoding", e);
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.decode(encryptedText));
            return new String(original);
        } catch (GeneralSecurityException e) {
            throw new OperationFailureExceptions("Error occurred while decrypting the encrypted text", e);
        }
    }

    /**
     * Get the loaded properties from the proxy.properties file.
     *
     * @param key property key.
     * @return String property value.
     */
    public static String getProperty(String key) {

        if (properties == null || properties.isEmpty()) {
            try {
                properties = new Properties();
                // From Class, the path is relative to the package of the class unless you include a leading slash,
                // so if you don't want to use the current package, include a slash at the beginning as follows.
                // ProxyUtils.class.getClassLoader().getResourceAsStream("/" + PROXY_PROPERTIES_FILE);
                // From ClassLoader, all paths are "absolute" already - there's no context from which they could be
                // relative. Therefore you don't need a leading slash.
                InputStream inputStream = ProxyUtils.class.getClassLoader().getResourceAsStream(PROXY_PROPERTIES_FILE);
                properties.load(inputStream);
                inputStream.close();
                if (log.isDebugEnabled()) {
                    log.info("Util properties loaded successfully from: " + PROXY_PROPERTIES_FILE);
                }
            } catch (IOException e) {
                // Throws a RuntimeException in order to stop the proxy when property file cannot be read.
                throw new RuntimeException("Failed to load the util properties from: " + PROXY_PROPERTIES_FILE, e);
            }
        }
        return  (String) properties.get(key);
    }
}
