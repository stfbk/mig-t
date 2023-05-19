import migt.HTTPReqRes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class HTTPReqRes_Test {

    public HTTPReqRes initMessage_ok() {
        String raw = "POST /log?format=json&hasfast=true&authuser=0 HTTP/2\r\n" +
                "Host: play.google.com\r\n" +
                "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n" +
                "Content-Length: 11\r\n" +
                "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n" +
                "Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n" +
                "X-Goog-Authuser: 0\r\n" +
                "Sec-Ch-Ua-Mobile: ?0\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n" +
                "Sec-Ch-Ua-Platform: \"Linux\"\r\n" +
                "Accept: */*\r\n" +
                "Origin: https://www.google.com\r\n" +
                "X-Client-Data: CNiKywE=\r\n" +
                "Sec-Fetch-Site: same-site\r\n" +
                "Sec-Fetch-Mode: cors\r\n" +
                "Sec-Fetch-Dest: empty\r\n" +
                "Referer: https://www.google.com/\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Accept-Language: en-US,en;q=0.9\r\n" +
                "\r\n";

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
        message.setRequest_url("https://play.google.com/log?format=json&hasfast=true&authuser=0");

        return message;
    }

    @Test
    @DisplayName("")
    public void test_build() {
        String raw = "POST /log?format=json&hasfast=true&authuser=0 HTTP/2\r\n" +
                "Host: play.google.com\r\n" +
                "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n" +
                "Content-Length: 11\r\n" +
                "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n" +
                "Content-Type: application/x-www-form-urlencoded;charset=UTF-8\r\n" +
                "X-Goog-Authuser: 0\r\n" +
                "Sec-Ch-Ua-Mobile: ?0\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n" +
                "Sec-Ch-Ua-Platform: \"Linux\"\r\n" +
                "Accept: */*\r\n" +
                "Origin: https://www.google.com\r\n" +
                "X-Client-Data: CNiKywE=\r\n" +
                "Sec-Fetch-Site: same-site\r\n" +
                "Sec-Fetch-Mode: cors\r\n" +
                "Sec-Fetch-Dest: empty\r\n" +
                "Referer: https://www.google.com/\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Accept-Language: en-US,en;q=0.9\r\n" +
                "\r\n";

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
        String raw = "POST /log?format=json&hasfast=true&authuser=0 HTTP/2\r\n" +
                "Host: play.google.com\r\n" +
                "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n" +
                "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n" +
                "X-Goog-Authuser: 0\r\n" +
                "Sec-Ch-Ua-Mobile: ?0\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n" +
                "Sec-Ch-Ua-Platform: \"Linux\"\r\n" +
                "Accept: */*\r\n" +
                "Origin: https://www.google.com\r\n" +
                "X-Client-Data: CNiKywE=\r\n" +
                "Sec-Fetch-Site: same-site\r\n" +
                "Sec-Fetch-Mode: cors\r\n" +
                "Sec-Fetch-Dest: empty\r\n" +
                "Referer: https://www.google.com/\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Accept-Language: en-US,en;q=0.9\r\n" +
                "\r\n";

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
        String raw = "POST /log?format=json&hasfast=true&authuser=0 HTTP/2\r\n" +
                "Host: play.google.com\r\n" +
                "Cookie: CONSENT=PENDING+392; SOCS=CAISHAgCEhJnd3NfMjAyMzAyMjgtMF9SQzIaAml0IAEaBgiA2pSgBg; AEC=AUEFqZdSS4hmP6dNNRrldXefJFuHK2ldiLrZLJG24hUqaFA2L0jJxZwSBA; NID=511=SPj3DZBbWBMVstxl414okznEMUOaUHRzxZehEHxoaTi0Fr_X9RQ6UmFDBvI6wWn1Iivh7lzi_q7Ktri2q8hHc9nVY3XNgQP-IQ4AHNz7lCKra72IjxzhBvEBQFdXy7lEaIVC3wK5TfPIXLX3TWhKwrZAVEg77UkqV2oHYohcSXg\r\n" +
                "Sec-Ch-Ua: \"Chromium\";v=\"111\", \"Not(A:Brand\";v=\"8\"\r\n" +
                "Content-Length: 11\r\n" +
                "X-Goog-Authuser: 0\r\n" +
                "Sec-Ch-Ua-Mobile: ?0\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.65 Safari/537.36\r\n" +
                "Sec-Ch-Ua-Platform: \"Linux\"\r\n" +
                "Accept: */*\r\n" +
                "Origin: https://www.google.com\r\n" +
                "X-Client-Data: CNiKywE=\r\n" +
                "Sec-Fetch-Site: same-site\r\n" +
                "Sec-Fetch-Mode: cors\r\n" +
                "Sec-Fetch-Dest: empty\r\n" +
                "Referer: https://www.google.com/\r\n" +
                "Accept-Encoding: gzip, deflate\r\n" +
                "Accept-Language: en-US,en;q=0.9\r\n" +
                "\r\n";

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

        assertEquals("POST /log?format=json&hasfast=true&authuser=0 HTTP/2", header_0);
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
}
