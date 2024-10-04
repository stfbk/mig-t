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
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.HTTPReqRes;
import org.zaproxy.addon.migt.ParsingException;

public class HTTPReqRes_Test {

    public static HTTPReqRes initMessage_ok() {
        String raw =
                "POST /log?format=json&hasfast=true&authuser=0&paramwithspace=first+last HTTPS/2\r\n"
                        + "Host: play.google.com\r\n"
                        + "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n"
                        + "Content-Length: 11\r\n"
                        + "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n"
                        + "Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n"
                        + "X-Goog-Authuser: 0\r\n"
                        + "Sec-Ch-Ua-Mobile: ?0\r\n"
                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n"
                        + "Sec-Ch-Ua-Platform: \"Linux\"\r\n"
                        + "Accept: */*\r\n"
                        + "Origin: https://www.google.com\r\n"
                        + "X-Client-Data: CNiKywE=\r\n"
                        + "Sec-Fetch-Site: same-site\r\n"
                        + "Sec-Fetch-Mode: cors\r\n"
                        + "Sec-Fetch-Dest: empty\r\n"
                        + "Referer: https://www.google.com/\r\n"
                        + "Accept-Encoding: gzip, deflate\r\n"
                        + "Accept-Language: en-US,en;q=0.9\r\n"
                        + "\r\n";

        List<String> headers = new ArrayList<>();

        Collections.addAll(headers, raw.split("\r\n"));

        int body_offset = raw.length();

        raw += "bodycontent";

        byte[] raw_b = raw.getBytes(StandardCharsets.UTF_8);

        HTTPReqRes message = new HTTPReqRes(raw_b, null);

        message.body_offset_req = body_offset;
        message.setHeaders(true, headers);
        message.isRequest = true;
        message.isResponse = false;
        message.setRequest_url(
                "https://play.google.com/log?format=json&hasfast=true&authuser=0&paramwithspace=first+last");

        return message;
    }

    public HTTPReqRes init_message_no_body() {
        String raw =
                "POST /log?format=json&hasfast=true&authuser=0&paramwithspace=first+last HTTPS/2\r\n"
                        + "Host: play.google.com\r\n"
                        + "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n"
                        + "Content-Length: 11\r\n"
                        + "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n"
                        + "Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n"
                        + "X-Goog-Authuser: 0\r\n"
                        + "Sec-Ch-Ua-Mobile: ?0\r\n"
                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n"
                        + "Sec-Ch-Ua-Platform: \"Linux\"\r\n"
                        + "Accept: */*\r\n"
                        + "Origin: https://www.google.com\r\n"
                        + "X-Client-Data: CNiKywE=\r\n"
                        + "Sec-Fetch-Site: same-site\r\n"
                        + "Sec-Fetch-Mode: cors\r\n"
                        + "Sec-Fetch-Dest: empty\r\n"
                        + "Referer: https://www.google.com/\r\n"
                        + "Accept-Encoding: gzip, deflate\r\n"
                        + "Accept-Language: en-US,en;q=0.9\r\n"
                        + "\r\n";

        List<String> headers = new ArrayList<>();

        Collections.addAll(headers, raw.split("\r\n"));

        byte[] raw_b = raw.getBytes(StandardCharsets.UTF_8);

        HTTPReqRes message = new HTTPReqRes(raw_b, null);

        message.body_offset_req = 0;
        message.setHeaders(true, headers);
        message.isRequest = true;
        message.isResponse = false;
        message.setRequest_url(
                "https://play.google.com/log?format=json&hasfast=true&authuser=0&paramwithspace=first+last");

        return message;
    }

    @Test
    @DisplayName("")
    public void test_build() {
        String raw =
                "POST /log?format=json&hasfast=true&authuser=0&paramwithspace=first+last HTTP/2\r\n"
                        + "Host: play.google.com\r\n"
                        + "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n"
                        + "Content-Length: 11\r\n"
                        + "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n"
                        + "Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n"
                        + "X-Goog-Authuser: 0\r\n"
                        + "Sec-Ch-Ua-Mobile: ?0\r\n"
                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n"
                        + "Sec-Ch-Ua-Platform: \"Linux\"\r\n"
                        + "Accept: */*\r\n"
                        + "Origin: https://www.google.com\r\n"
                        + "X-Client-Data: CNiKywE=\r\n"
                        + "Sec-Fetch-Site: same-site\r\n"
                        + "Sec-Fetch-Mode: cors\r\n"
                        + "Sec-Fetch-Dest: empty\r\n"
                        + "Referer: https://www.google.com/\r\n"
                        + "Accept-Encoding: gzip, deflate\r\n"
                        + "Accept-Language: en-US,en;q=0.9\r\n"
                        + "\r\n";

        List<String> headers = List.of(raw.split("\r\n"));

        int body_offset = raw.length();

        raw += "bodycontent";

        byte[] raw_b = raw.getBytes(StandardCharsets.UTF_8);

        HTTPReqRes message = new HTTPReqRes(raw_b, null);
        message.body_offset_req = body_offset;
        message.setHeaders(true, headers);

        byte[] builded = message.build_message(message.isRequest);
        String builded_str = new String(builded, StandardCharsets.UTF_8);
        assertEquals(raw, builded_str);
        assertArrayEquals(builded, raw_b);
    }

    @Test
    @DisplayName("")
    public void test_build_no_body() {
        String raw =
                "POST /log?format=json&hasfast=true&authuser=0&paramwithspace=first+last HTTP/2\r\n"
                        + "Host: play.google.com\r\n"
                        + "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n"
                        + "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n"
                        + "X-Goog-Authuser: 0\r\n"
                        + "Sec-Ch-Ua-Mobile: ?0\r\n"
                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n"
                        + "Sec-Ch-Ua-Platform: \"Linux\"\r\n"
                        + "Accept: */*\r\n"
                        + "Origin: https://www.google.com\r\n"
                        + "X-Client-Data: CNiKywE=\r\n"
                        + "Sec-Fetch-Site: same-site\r\n"
                        + "Sec-Fetch-Mode: cors\r\n"
                        + "Sec-Fetch-Dest: empty\r\n"
                        + "Referer: https://www.google.com/\r\n"
                        + "Accept-Encoding: gzip, deflate\r\n"
                        + "Accept-Language: en-US,en;q=0.9\r\n"
                        + "\r\n";

        List<String> headers = List.of(raw.split("\r\n"));

        int body_offset = raw.length();

        byte[] raw_b = raw.getBytes(StandardCharsets.UTF_8);

        HTTPReqRes message = new HTTPReqRes(raw_b, null);
        message.body_offset_req = body_offset;
        message.setHeaders(true, headers);

        byte[] builded = message.build_message(message.isRequest);
        String builded_str = new String(builded, StandardCharsets.UTF_8);
        assertEquals(raw, builded_str);
        assertArrayEquals(builded, raw_b);
    }

    @Test
    @DisplayName("")
    public void test_build_no_body_with_content_len() {
        String raw =
                "POST /log?format=json&hasfast=true&authuser=0&paramwithspace=first+last HTTP/2\r\n"
                        + "Host: play.google.com\r\n"
                        + "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n"
                        + "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n"
                        + "Content-Length: 11\r\n"
                        + "X-Goog-Authuser: 0\r\n"
                        + "Sec-Ch-Ua-Mobile: ?0\r\n"
                        + "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n"
                        + "Sec-Ch-Ua-Platform: \"Linux\"\r\n"
                        + "Accept: */*\r\n"
                        + "Origin: https://www.google.com\r\n"
                        + "X-Client-Data: CNiKywE=\r\n"
                        + "Sec-Fetch-Site: same-site\r\n"
                        + "Sec-Fetch-Mode: cors\r\n"
                        + "Sec-Fetch-Dest: empty\r\n"
                        + "Referer: https://www.google.com/\r\n"
                        + "Accept-Encoding: gzip, deflate\r\n"
                        + "Accept-Language: en-US,en;q=0.9\r\n"
                        + "\r\n";

        List<String> headers = List.of(raw.split("\r\n"));

        int body_offset = raw.length();

        byte[] raw_b = raw.getBytes(StandardCharsets.UTF_8);

        HTTPReqRes message = new HTTPReqRes(raw_b, null);
        message.body_offset_req = body_offset;
        message.setHeaders(true, headers);

        byte[] builded = message.build_message(message.isRequest);
        String builded_str = new String(builded, StandardCharsets.UTF_8);

        raw = raw.replace("Content-Length: 11\r\n", "");
        raw_b = raw.getBytes(StandardCharsets.UTF_8);

        assertEquals(raw, builded_str);
        assertArrayEquals(builded, raw_b);
    }

    @Test
    @DisplayName("")
    public void test_getUrlHeader() {
        HTTPReqRes message = initMessage_ok();
        String header_0 = message.getUrlHeader();

        assertEquals(
                "POST /log?format=json&hasfast=true&authuser=0&paramwithspace=first+last HTTPS/2",
                header_0);
    }

    @Test
    @DisplayName("")
    public void test_getUrlParam() {
        HTTPReqRes message = initMessage_ok();
        String value = message.getUrlParam("format");
        assertEquals("json", value);
        value = message.getUrlParam("hasfast");
        assertEquals("true", value);
        value = message.getUrlParam("authuser");
        assertEquals("0", value);
    }

    @Test
    @DisplayName("")
    public void test_editUrlParam() throws ParsingException {
        HTTPReqRes message = initMessage_ok();
        message.editUrlParam("format", "new");
        assertEquals(
                "https://play.google.com/log?format=new&hasfast=true&authuser=0&paramwithspace=first+last",
                message.getUrl());
        message.setRequest_url(
                "https://play.google.com:8080/log?format=new&hasfast=true&authuser=0#123123123");
        message.editUrlParam("format", "newnew");
        assertEquals(
                "https://play.google.com:8080/log?format=newnew&hasfast=true&authuser=0#123123123",
                message.getUrl());
        assertEquals(
                "POST /log?format=newnew&hasfast=true&authuser=0 HTTPS/2", message.getUrlHeader());
    }

    @Test
    public void test_url_update_header_0() {
        HTTPReqRes message = initMessage_ok();
        message.setRequest_url(
                "https://play.google.com:8080/log?format=newnew&hasfast=true&authuser=0#123123123");
        assertEquals(
                "https://play.google.com:8080/log?format=newnew&hasfast=true&authuser=0#123123123",
                message.getUrl());
        assertEquals(
                "POST /log?format=newnew&hasfast=true&authuser=0 HTTPS/2", message.getUrlHeader());
    }

    @Test
    public void test_editUrlHeaders() throws ParsingException {
        HTTPReqRes message = initMessage_ok();
        message.updateHeadersWHurl();
        assertEquals(
                "POST /log?format=json&hasfast=true&authuser=0&paramwithspace=first+last HTTPS/2",
                message.getHeaders(true).get(0));
        message.editUrlParam("format", "new");
        assertEquals(
                "POST /log?format=new&hasfast=true&authuser=0&paramwithspace=first+last HTTPS/2",
                message.getHeaders(true).get(0));
        message.removeUrlParam("hasfast");
        assertEquals(
                "POST /log?format=new&authuser=0&paramwithspace=first+last HTTPS/2",
                message.getHeaders(true).get(0));
        message.addUrlParam("prova", "provona");
        assertEquals(
                "POST /log?format=new&authuser=0&paramwithspace=first+last&prova=provona HTTPS/2",
                message.getHeaders(true).get(0));
    }

    @Test
    @DisplayName("")
    public void test_removeUrlParam() throws ParsingException {
        HTTPReqRes message = initMessage_ok();
        message.removeUrlParam("format");
        assertEquals(
                "https://play.google.com/log?hasfast=true&authuser=0&paramwithspace=first+last",
                message.getUrl());
    }

    @Test
    @DisplayName("")
    public void test_addUrlParam() throws ParsingException {
        HTTPReqRes message = initMessage_ok();
        message.addUrlParam("test", "test");
        assertEquals(
                "https://play.google.com/log?format=json&hasfast=true&authuser=0&paramwithspace=first+last&test=test",
                message.getUrl());
    }

    @Test
    @DisplayName("")
    public void test_getHeadParam() {
        HTTPReqRes message = initMessage_ok();
        String value = message.getHeadParam(true, "Origin");
        assertEquals("https://www.google.com", value);
    }

    @Test
    @DisplayName("")
    public void test_editHeadParam() {
        HTTPReqRes message = initMessage_ok();
        message.editHeadParam(true, "Origin", "www.another.com");
        String value = message.getHeadParam(true, "Origin");
        assertEquals("www.another.com", value);
    }

    @Test
    @DisplayName("")
    public void test_addHeadParameter() {
        HTTPReqRes message = initMessage_ok();
        message.addHeadParameter(true, "Test", "valuetest");
        String value = message.getHeadParam(true, "Test");
        assertEquals("valuetest", value);
    }

    @Test
    @DisplayName("")
    public void test_removeHeadParameter() {
        HTTPReqRes message = initMessage_ok();
        message.removeHeadParameter(true, "Origin");
        String value = message.getHeadParam(true, "Origin");
        assertEquals("", value);
    }

    @Test
    public void test_add_body() {
        // add body to a message that does not have it
        HTTPReqRes message = init_message_no_body();
        assertFalse(message.hasBody(true));

        message.addBody(true, "testbodycontent");

        assertTrue(message.hasBody(true));
        assertEquals("testbodycontent", new String(message.getBody(true)));

        message.addBody(true, "1");
        assertEquals("testbodycontent1", new String(message.getBody(true)));
    }

    @Test
    public void test_edit_body_regex() {
        HTTPReqRes message = initMessage_ok();

        message.editBodyRegex(true, "conte", "1234");
        assertEquals("body1234nt", new String(message.getBody(true)));
    }

    @Test
    public void test_get_url_param_no_urlencode() {
        HTTPReqRes msg = initMessage_ok();

        // with url encode (default)
        String value = msg.getUrlParam("paramwithspace");
        assertEquals("first last", value);

        // without url encode
        value = msg.getUrlParam("paramwithspace", true);
        assertEquals("first+last", value);
    }
}
