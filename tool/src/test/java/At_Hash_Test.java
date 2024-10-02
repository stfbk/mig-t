/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.At_Hash_check;
import org.zaproxy.addon.migt.HTTPReqRes;
import org.zaproxy.addon.migt.Operation_API;

public class At_Hash_Test {

    public HTTPReqRes init_message_token_resp() {
        String raw =
                "HTTP/1.1 200 OK\r\n"
                        + "Date: Fri, 22 Dec 2023 13:12:13 GMT\r\n"
                        + "Server: WSGIServer/0.2 CPython/3.10.13\r\n"
                        + "Content-Type: application/json\r\n"
                        + "X-Frame-Options: DENY\r\n"
                        + "Content-Length: 2037\r\n"
                        + "X-Content-Type-Options: nosniff\r\n"
                        + "Referrer-Policy: same-origin\r\n"
                        + "Cross-Origin-Opener-Policy: same-origin\r\n"
                        + "\r\n";

        List<String> headers = new ArrayList<>();

        Collections.addAll(headers, raw.split("\r\n"));

        int body_offset = raw.length();

        raw +=
                "{\"access_token\": \"eyJ0eXAiOiJhdCtqd3QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlBkMk45LVRael9BV1MzR0ZDa29ZZFJhWFhsczhZUGh4X2RfRXo3SndqUUkifQ.eyJpc3MiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AiLCJzdWIiOiIyMmE4M2FhZmRlOWUyYzhkZmU2MzM1NTk3ZDk1MTNlMzYzMDdhOWI0NjI1NjVkYTg4MzM5ZTQzMDEyOGE0ODlhIiwiYXVkIjpbImh0dHA6Ly9jaWUtcHJvdmlkZXIub3JnOjgwMDIvb2lkYy9vcCIsIi9vaWRjL29wL3VzZXJpbmZvIl0sImNsaWVudF9pZCI6Imh0dHA6Ly9yZWx5aW5nLXBhcnR5Lm9yZzo4MDAxIiwic2NvcGUiOiJvcGVuaWQgb2ZmbGluZV9hY2Nlc3MiLCJqdGkiOiJmMTA0MWMxYi1hNDYyLTQ3ZWYtOTJjNi0zYWU0ZDNkZTgzMjIiLCJleHAiOjE3MDMyNTI3MTMsImlhdCI6MTcwMzI1MDczM30.bSlYNNyB8zdvE4M-9aiMEeI9NAsd12w47BCb_5ywZqLZMEJ06NYSHzhnJKzonh2TW32I9VFeB8ZxlyTmiFpaLuTm4onN2FfHIWeWYgwwAo-0JgUdjNGS07Vy4EkqZeFChDJCcI4uUriIFEG4u2dnTILNjJC1qcjA3CIlPn7kz9RkDfGw4zAFlOQZ9oVJj5LFUHfB7oDem2z0uJehw5gXHEVBi0hcA1Lj10i8rVuTqhRfCoOdxZwBuTq7eH6z6jCSIplyPIhVqY-dhGQrDvR_tMY4Ulz7Xd0EVjvs09H9QT1tDz9e8WNTF_UbQV8nEaTkbOzN9AC9C0JdJ76O0kH_yg\", \"id_token\": \"eyJhbGciOiJSUzI1NiIsImtpZCI6IlBkMk45LVRael9BV1MzR0ZDa29ZZFJhWFhsczhZUGh4X2RfRXo3SndqUUkifQ.eyJzdWIiOiIyMmE4M2FhZmRlOWUyYzhkZmU2MzM1NTk3ZDk1MTNlMzYzMDdhOWI0NjI1NjVkYTg4MzM5ZTQzMDEyOGE0ODlhIiwibm9uY2UiOiJFNzdKenN0NDNNdjNsUmNyZ2lSRW01U3lRNjNCMTd4VyIsImF0X2hhc2giOiJhVDVmd21tNmFaZmdoTUpYNGZ0Q0N3IiwiY19oYXNoIjoiZm8wVHB3cDRMVm03MmhwcFNsVVpLUSIsImF1ZCI6WyJodHRwOi8vcmVseWluZy1wYXJ0eS5vcmc6ODAwMSJdLCJpc3MiOiJodHRwOi8vY2llLXByb3ZpZGVyLm9yZzo4MDAyL29pZGMvb3AiLCJhY3IiOiJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDIiLCJqdGkiOiJiYjE5ZGUwYi0xNGQ3LTQzNGEtOTVmNS1jMWRlNWNhNzhkNWQiLCJmYW1pbHlfbmFtZSI6Im1hcmFkb25hIiwiZ2l2ZW5fbmFtZSI6InBlcHBlIiwiZXhwIjoxNzAzMjUyNzEzLCJpYXQiOjE3MDMyNTA3MzN9.h6cUctsaauPpwgPlL_S5A1v_FxWsgAPh1lppizSOwmw0k0r8XlA8EhxXF7NuTG0fyF-TvIR-XzjOovZyv7nfp2uTExzwjBK36S9qixRlLdZeAP5keMTzBGQRAvRzf3xCfdbo9Hz3wdFVAaZL4owbFZJrEf79j6bkJ7EYWPpaxgT2iWoaBDLNBh9cNhRAisBjpKF7Pg9Qjcgh06JBWTdcaGXxt7RITNhh03_kXNmHXc1tNyHqBMhUfPpdDgn0qzbhRm4lRPKg93sMvLTpyETsPsTiVrlBZqZpR-0DpSDRWibCw40vcPS0fbRgHZUWmrxPiyqh9e7hr3MM2Gbejg8THg\", \"token_type\": \"Bearer\", \"expires_in\": 1980, \"scope\": \"openid offline_access\"}";
        byte[] raw_b = raw.getBytes(StandardCharsets.UTF_8);

        HTTPReqRes message = new HTTPReqRes(null, raw_b);
        message.body_offset_resp = body_offset;
        message.setHeaders(false, headers);
        message.isResponse = true;
        message.isRequest = false;

        return message;
    }

    @Test
    public void test_At_Hash() throws NoSuchAlgorithmException {
        HTTPReqRes test_message = init_message_token_resp();

        At_Hash_check ah = new At_Hash_check();

        Operation_API o = new Operation_API(test_message, false);

        ah.loader(o);
        ah.execute();
        assertTrue(ah.getResult());
    }
}
