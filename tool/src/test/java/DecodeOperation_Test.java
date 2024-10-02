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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.DecodeOperation;
import org.zaproxy.addon.migt.DecodeOperation_API;
import org.zaproxy.addon.migt.HTTPReqRes;
import org.zaproxy.addon.migt.Operation_API;
import org.zaproxy.addon.migt.ParsingException;

public class DecodeOperation_Test {
    String input =
            "{\n"
                    + "    \"from\": \"url\",\n"
                    + "    \"type\": \"jwt\",\n"
                    + "    \"decode param\": \"asd\",\n"
                    + "    \"decode operations\": [\n"
                    + "      {\n"
                    + "        \"from\": \"jwt header\",\n"
                    + "        \"type\": \"jwt\",\n"
                    + "        \"decode param\": \"$.something\"\n"
                    + "      }\n"
                    + "    ]\n"
                    + "  }";

    String input_w_checks =
            "{\n"
                    + "                \"from\": \"body\",\n"
                    + "                \"decode param\": \"(?<=authz_request_object=)[^$\\n& ]*\",\n"
                    + "                \"type\": \"jwt\",\n"
                    + "                \"checks\": [\n"
                    + "                  {\n"
                    + "                    \"in\": \"payload\",\n"
                    + "                    \"check\": \"$.scope\",\n"
                    + "                    \"is\": \"openid\"\n"
                    + "                  }\n"
                    + "                ]\n"
                    + "              }";

    String input_w_edits =
            "{\n"
                    + "                \"from\": \"body\",\n"
                    + "                \"decode param\": \"(?<=authz_request_object=)[^$\\n& ]*\",\n"
                    + "                \"type\": \"jwt\",\n"
                    + "                \"edits\": [\n"
                    + "                  {\n"
                    + "                    \"jwt from\": \"payload\",\n"
                    + "                    \"jwt edit\": \"$.scope\",\n"
                    + "                    \"value\": \"qualcosaltro\"\n"
                    + "                  }\n"
                    + "                ]\n"
                    + "              }";

    String input_w_edits_save =
            "{\n"
                    + "                \"from\": \"body\",\n"
                    + "                \"decode param\": \"(?<=authz_request_object=)[^$\\n& ]*\",\n"
                    + "                \"type\": \"jwt\",\n"
                    + "                \"edits\": [\n"
                    + "                  {\n"
                    + "                    \"jwt from\": \"payload\",\n"
                    + "                    \"jwt save\": \"$.scope\",\n"
                    + "                    \"as\": \"varname\"\n"
                    + "                  }\n"
                    + "                ]\n"
                    + "              }";

    public static HTTPReqRes get_test_message_with_jwt() {
        String req =
                "GET /.well-known/openid-federation HTTP/1.1\n"
                        + "Host: trust-anchor.org:8000\n"
                        + "Accept: */*\n"
                        + "Accept-Encoding: gzip, deflate\n"
                        + "User-Agent: Python/3.10 aiohttp/3.9.3\n"
                        + "Connection: close\n"
                        + "\n";

        String resp =
                "HTTP/1.1 200 OK\n"
                        + "Date: Wed, 13 Mar 2024 10:31:06 GMT\n"
                        + "Server: WSGIServer/0.2 CPython/3.10.13\n"
                        + "Content-Type: application/entity-statement+jwt\n"
                        + "X-Frame-Options: DENY\n"
                        + "Content-Length: 2464\n"
                        + "X-Content-Type-Options: nosniff\n"
                        + "Referrer-Policy: same-origin\n"
                        + "Cross-Origin-Opener-Policy: same-origin\n"
                        + "\n"
                        + "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiQlh2ZnJsbmhBTXVIUjA3YWpVbUFjQlJRY1N6bXcwY19SQWdKbnBTLTlXUSJ9.eyJleHAiOjE3MTAzMjc4NDYsImlhdCI6MTcxMDMyNTg2NiwiaXNzIjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMCIsInN1YiI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsIm4iOiJvOElvbFJqWmxremN0LTQ4cmhyVmxUbllVMXBrTWJWSkQtRFUwNW9NUzlSVkdyc0Z5cGc5OG0tS3c0SDRxTlB5UVZ4Mk9RT1JpLXhTaGdrN0hVLWdLXzJwVmd1WWt2MDZGYWpMX2VkRUFxcXNxdF83NFFmMldMUkM1cGZKR196OU9Qelk4Skd5ay16M1NiZUhOX0JYS0k4R1k1RTRXVTJTc3RtUTlmeUw0Q3h0UmZqVWlhOGxpbVRDXzNNT3BUM3ppNW5yMDNqZmJqcG5qZ2E1MXFYdXJ4bmx6YzNhX3hqazVSQUFwS3hVdk53aEoyNzVNMENtQjk5RGpQd0Y2Qkx2VWdKcWd5Q3BVT24zNkxPaEk0RnF1VnFocWhpd0tsTW1pTWUzeXkweU5RN0ZYQld4anpoZXhicHljM1Z1N3pGSUhQQWNDNFV5SVFoYzN3YUVqMnZpWHciLCJlIjoiQVFBQiIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JSUWNTem13MGNfUkFnSm5wUy05V1EifV19LCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJjb250YWN0cyI6WyJvcHNAbG9jYWxob3N0Il0sImZlZGVyYXRpb25fZmV0Y2hfZW5kcG9pbnQiOiJodHRwOi8vdHJ1c3QtYW5jaG9yLm9yZzo4MDAwL2ZldGNoIiwiZmVkZXJhdGlvbl9yZXNvbHZlX2VuZHBvaW50IjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMC9yZXNvbHZlIiwiZmVkZXJhdGlvbl90cnVzdF9tYXJrX3N0YXR1c19lbmRwb2ludCI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvdHJ1c3RfbWFya19zdGF0dXMiLCJob21lcGFnZV91cmkiOiJodHRwOi8vdHJ1c3QtYW5jaG9yLm9yZzo4MDAwIiwib3JnYW5pemF0aW9uX25hbWUiOiJleGFtcGxlIFRBIiwicG9saWN5X3VyaSI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvZW4vd2Vic2l0ZS9sZWdhbC1pbmZvcm1hdGlvbiIsImxvZ29fdXJpIjoiaHR0cDovL3RydXN0LWFuY2hvci5vcmc6ODAwMC9zdGF0aWMvc3ZnL3NwaWQtbG9nby1jLWxiLnN2ZyIsImZlZGVyYXRpb25fbGlzdF9lbmRwb2ludCI6Imh0dHA6Ly90cnVzdC1hbmNob3Iub3JnOjgwMDAvbGlzdCJ9fSwidHJ1c3RfbWFya19pc3N1ZXJzIjp7Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHVibGljIjpbImh0dHBzOi8vcmVnaXN0cnkuc3BpZC5hZ2lkLmdvdi5pdCIsImh0dHBzOi8vcHVibGljLmludGVybWVkaWFyeS5zcGlkLml0Il0sImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHJpdmF0ZSI6WyJodHRwczovL3JlZ2lzdHJ5LnNwaWQuYWdpZC5nb3YuaXQiLCJodHRwczovL3ByaXZhdGUub3RoZXIuaW50ZXJtZWRpYXJ5Lml0Il0sImh0dHBzOi8vc2dkLmFhLml0L29uYm9hcmRpbmciOlsiaHR0cHM6Ly9zZ2QuYWEuaXQiXX0sImNvbnN0cmFpbnRzIjp7Im1heF9wYXRoX2xlbmd0aCI6MX19.XfNyESWn60pKcxd-g_fThaV0ig59GZgPkULIrKedEq1MBXpTchwrlSrpI490bSWIsgSARqtugXRMl6fqNhJfty82patlWGTPaYHvCd_6xOo-juRZC-WYn9zSIEw320SLA8FzDeGKIx_ny_vyv6Q2xVQt0BVE5ICngrFgxsLNQ1KOLo4l3EdorEJt8E18zGrB_bPwkMwIHg8smV5MAmWo9mc-4g4ZDRG2-BB2F2tVyavYa_eFPC-lhQSkmKMgtOh4m0QgslANfTKbT8Ce0dsDDrsjujUsiLCwXfwSVR_r9lbAm4tC-TQitpLregoGJYsD5SkEpbSTyWUGTGBvEcXBtg";

        HTTPReqRes res = new HTTPReqRes(req.getBytes(), resp.getBytes());
        res.body_offset_resp = 283;

        return res;
    }

    @Test
    void test_parse() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input));

        assertEquals(DecodeOperation.DecodeOperationFrom.URL, dop.from);
        assertEquals("asd", dop.decode_target);
        assertEquals(1, dop.decodeOperations.size());

        DecodeOperation child_dop = dop.decodeOperations.get(0);
        assertEquals(DecodeOperation.DecodeOperationFrom.JWT_HEADER, child_dop.from);
        assertEquals("$.something", child_dop.decode_target);
    }

    @Test
    void test_parse_w_checks() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_checks));

        assertEquals(DecodeOperation.DecodeOperationFrom.BODY, dop.from);
        assertEquals(1, dop.checks.size());
    }

    @Test
    void test_parse_w_edits() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_edits));

        assertEquals(1, dop.editOperations.size());
    }

    @Test
    void test_parse_w_edits_save() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_edits_save));

        assertEquals(1, dop.editOperations.size());
    }

    @Test
    void test_print_extended() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_edits_save));
        System.out.println(dop.toStringExtended());
    }

    @Test
    void test_decode_jwt() throws ParsingException {
        String in =
                "{\n"
                        + "    \"from\": \"body\",\n"
                        + "    \"type\": \"jwt\",\n"
                        + "    \"decode regex\": \"[^\\\\n\\\\r]*\"\n"
                        + "}";
        DecodeOperation dop = new DecodeOperation(new JSONObject(in));

        Operation_API op_api = new Operation_API(null);
        op_api.message = get_test_message_with_jwt();

        dop.loader(op_api);
        dop.execute(null);
        assertTrue(dop.getResult());
        DecodeOperation_API dop_api = dop.getAPI();
        assertEquals(
                "{\"exp\":1710327846,\"iat\":1710325866,\"iss\":\"http://trust-anchor.org:8000\",\"sub\":\"http://trust-anchor.org:8000\",\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"n\":\"o8IolRjZlkzct-48rhrVlTnYU1pkMbVJD-DU05oMS9RVGrsFypg98m-Kw4H4qNPyQVx2OQORi-xShgk7HU-gK_2pVguYkv06FajL_edEAqqsqt_74Qf2WLRC5pfJG_z9OPzY8JGyk-z3SbeHN_BXKI8GY5E4WU2SstmQ9fyL4CxtRfjUia8limTC_3MOpT3zi5nr03jfbjpnjga51qXurxnlzc3a_xjk5RAApKxUvNwhJ275M0CmB99DjPwF6BLvUgJqgyCpUOn36LOhI4FquVqhqhiwKlMmiMe3yy0yNQ7FXBWxjzhexbpyc3Vu7zFIHPAcC4UyIQhc3waEj2viXw\",\"e\":\"AQAB\",\"kid\":\"BXvfrlnhAMuHR07ajUmAcBRQcSzmw0c_RAgJnpS-9WQ\"}]},\"metadata\":{\"federation_entity\":{\"contacts\":[\"ops@localhost\"],\"federation_fetch_endpoint\":\"http://trust-anchor.org:8000/fetch\",\"federation_resolve_endpoint\":\"http://trust-anchor.org:8000/resolve\",\"federation_trust_mark_status_endpoint\":\"http://trust-anchor.org:8000/trust_mark_status\",\"homepage_uri\":\"http://trust-anchor.org:8000\",\"organization_name\":\"example TA\",\"policy_uri\":\"http://trust-anchor.org:8000/en/website/legal-information\",\"logo_uri\":\"http://trust-anchor.org:8000/static/svg/spid-logo-c-lb.svg\",\"federation_list_endpoint\":\"http://trust-anchor.org:8000/list\"}},\"trust_mark_issuers\":{\"https://www.spid.gov.it/certification/rp/public\":[\"https://registry.spid.agid.gov.it\",\"https://public.intermediary.spid.it\"],\"https://www.spid.gov.it/certification/rp/private\":[\"https://registry.spid.agid.gov.it\",\"https://private.other.intermediary.it\"],\"https://sgd.aa.it/onboarding\":[\"https://sgd.aa.it\"]},\"constraints\":{\"max_path_length\":1}}",
                dop_api.jwt.payload);
        assertEquals(
                "{\"kid\":\"BXvfrlnhAMuHR07ajUmAcBRQcSzmw0c_RAgJnpS-9WQ\",\"typ\":\"entity-statement+jwt\",\"alg\":\"RS256\"}",
                dop_api.jwt.header);
    }
}
