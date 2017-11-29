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

$(function () {
    var spaName = "mobileshop";
    var appSessionId = "appSessionId";

    // If there is no appSessionId in the session storage then user is not authenticated.
    // If so redirect to login page.
    if (!sessionStorage.getItem(appSessionId)) {
        redirectToLoginPage();
    } else {
        // Check the validity of the access-toke against the oauth-proxy.
        $.ajax({
            url: "https://localhost:8443/oauth2-proxy/authenticated",
            data: {
                'session-id' : sessionStorage.getItem(appSessionId)
            },
            // To make the ajax request synchronous.
            async: false,
            // To send cookie details for cross-domain calls
            xhrFields: {
                withCredentials: true
            },
            type: "GET",
            success: function (response) {
                if (!Boolean(response.authenticated)) {
                    redirectToLoginPage()
                }
            },
            error: function () {
                redirectToLoginPage();
            }
        });
    }

    // Setting the logout url.
    $('#logout-link').attr('href',
        "https://localhost:8443/oauth2-proxy/logout?session-id=" + sessionStorage.getItem(appSessionId));

    // Invokes backend dummy api.
    $('#api-proxy').click(function () {
        $.ajax({
            url: "https://localhost:8443/oauth2-proxy/api/oauth2-proxy/dummy/secured-resource?resource-name=pictures",
            beforeSend: function (request) {
                request.setRequestHeader("Spa-Session-Id", sessionStorage.getItem(appSessionId));
            },
            // To send cookie details for cross-domain calls
            xhrFields: {
                withCredentials: true
            },
            type: "GET",
            success: function (response) {
                $('#api-proxy-result').html(JSON.stringify(response));
            },
            error: function (error) {
                $('#api-proxy-result').html(JSON.stringify(error));
            }
        });
    });

    // Invokes userinfo endpoint.
    $('#is-userinfo').click(function () {
        $.ajax({
            url: "https://localhost:8443/oauth2-proxy/userinfo",
            data: {
                'session-id' : sessionStorage.getItem(appSessionId)
            },
            // To send cookie details for cross-domain calls
            xhrFields: {
                withCredentials: true
            },
            type: "GET",
            success: function (response) {
                $('#is-userinfo-result').html(JSON.stringify(response));
            },
            error: function (error) {
                $('#is-userinfo-result').html(JSON.stringify(error));
            }
        });
    });

    // Do an ajax call to the get the logged in user details.
    // On success show the name in the name-id element.
    $.ajax({
        url: "https://localhost:8443/oauth2-proxy/users",
        data: {
            'session-id': sessionStorage.getItem(appSessionId)
        },
        // To send cookie details for cross-domain calls
        xhrFields: {
            withCredentials: true
        },
        type: "GET",
        success: function (response, status, jqXHR) {
            // XHR readystate 4 is the done state.
            if (jqXHR.readyState == 4 && jqXHR.status == 200) {
                $('#name-id').html(response.sub);
            } else {
                redirectToLoginPage();
            }
        },
        error: function () {
            redirectToLoginPage();
        }
    });

    function redirectToLoginPage() {
        window.location = "index.html";
    }
});

