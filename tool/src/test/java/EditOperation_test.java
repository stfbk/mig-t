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
import org.zaproxy.addon.migt.EditOperation;
import org.zaproxy.addon.migt.HTTPReqRes;
import org.zaproxy.addon.migt.Operation_API;
import org.zaproxy.addon.migt.ParsingException;

public class EditOperation_test {
    HTTPReqRes message = HTTPReqRes_Test.initMessage_ok();
    HTTPReqRes message_w_body;

    @Test
    public void test_encode_url_param() throws ParsingException {
        String input =
                "{\"from\": \"url\", \"encode\": \"format\"," + "\"encodings\": [\"base64\"]}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("anNvbg==", res.message.getUrlParam("format"));
    }

    @Test
    public void test_encode_head_param() throws ParsingException {
        String input =
                "{\"from\": \"head\", \"encode\": \"Host\"," + "\"encodings\": [\"base64\"]}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("cGxheS5nb29nbGUuY29t", res.message.getHeadParam(true, "Host"));
    }

    @Test
    public void test_encode_body_param() throws ParsingException {
        String input = "{\"from\": \"body\", \"encode\": \".*\"," + "\"encodings\": [\"base64\"]}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("Ym9keWNvbnRlbnQ=", new String(res.message.getBody(true)));
    }

    @Test
    public void test_edit_url_regex() throws ParsingException {
        String input =
                "{\"from\": \"url\", \"edit regex\": \"format=json\","
                        + "\"value\": \"test=testone\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("testone", res.message.getUrlParam("test"));
    }

    @Test
    public void test_edit_head_regex() throws ParsingException {
        String input =
                "{\"from\": \"head\", \"edit regex\": \"Host:\"," + "\"value\": \"Hosted:\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("play.google.com", res.message.getHeadParam(true, "Hosted"));
    }

    @Test
    public void test_edit_body_regex() throws ParsingException {
        String input = "{\"from\": \"body\", \"edit regex\": \"ent\"," + "\"value\": \"123\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("bodycont123", new String(res.message.getBody(true)));
    }

    @Test
    public void test_add_url_param() throws ParsingException {
        String input = "{\"from\": \"url\", \"add\": \"codechallenge\"," + "\"value\": \"12345\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("12345", res.message.getUrlParam("codechallenge"));
    }

    @Test
    public void test_add_url_param_already_present() throws ParsingException {
        String input = "{\"from\": \"url\", \"add\": \"authuser\"," + "\"value\": \"1\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("01", res.message.getUrlParam("authuser"));
    }

    @Test
    public void test_add_head_param() throws ParsingException {
        String input = "{\"from\": \"head\", \"add\": \"Magicheader\"," + "\"value\": \"123123\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("123123", res.message.getHeadParam(true, "Magicheader"));
    }

    @Test
    public void test_add_head_param_already_present() throws ParsingException {
        String input = "{\"from\": \"head\", \"add\": \"Accept\"," + "\"value\": \"1\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("*/*1", res.message.getHeadParam(true, "Accept"));
    }

    @Test
    public void test_add_body() throws ParsingException {
        String input = "{\"from\": \"body\", \"add\": \"anything\"," + "\"value\": \"&appended\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("bodycontent&appended", new String(res.message.getBody(true)));
    }

    @Test
    public void test_add_json_jwt() throws ParsingException {
        String input =
                "{\n"
                        + "    \"from\": \"body\",\n"
                        + "    \"type\": \"jwt\",\n"
                        + "    \"decode regex\": \"[^\\\\n\\\\r]*\",\n"
                        + "    \"edits\": [\n"
                        + "        {\n"
                        + "            \"jwt from\": \"payload\",\n"
                        + "            \"jwt add\": \"$\",\n"
                        + "            \"key\": \"new\",\n"
                        + "            \"value\": \"valuenew\"\n"
                        + "        }\n"
                        + "    ]\n"
                        + "}";

        DecodeOperation dop = new DecodeOperation(new JSONObject(input));
        dop.loader(new Operation_API(DecodeOperation_Test.get_test_message_with_jwt(), false));

        dop.execute(null);
        assertTrue(dop.editOperations.get(0).getResult());

        assertEquals(
                "{\"exp\":1710327846,\"iat\":1710325866,\"iss\":\"http://trust-anchor.org:8000\",\"sub\":\"http://trust-anchor.org:8000\",\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"n\":\"o8IolRjZlkzct-48rhrVlTnYU1pkMbVJD-DU05oMS9RVGrsFypg98m-Kw4H4qNPyQVx2OQORi-xShgk7HU-gK_2pVguYkv06FajL_edEAqqsqt_74Qf2WLRC5pfJG_z9OPzY8JGyk-z3SbeHN_BXKI8GY5E4WU2SstmQ9fyL4CxtRfjUia8limTC_3MOpT3zi5nr03jfbjpnjga51qXurxnlzc3a_xjk5RAApKxUvNwhJ275M0CmB99DjPwF6BLvUgJqgyCpUOn36LOhI4FquVqhqhiwKlMmiMe3yy0yNQ7FXBWxjzhexbpyc3Vu7zFIHPAcC4UyIQhc3waEj2viXw\",\"e\":\"AQAB\",\"kid\":\"BXvfrlnhAMuHR07ajUmAcBRQcSzmw0c_RAgJnpS-9WQ\"}]},\"metadata\":{\"federation_entity\":{\"contacts\":[\"ops@localhost\"],\"federation_fetch_endpoint\":\"http://trust-anchor.org:8000/fetch\",\"federation_resolve_endpoint\":\"http://trust-anchor.org:8000/resolve\",\"federation_trust_mark_status_endpoint\":\"http://trust-anchor.org:8000/trust_mark_status\",\"homepage_uri\":\"http://trust-anchor.org:8000\",\"organization_name\":\"example TA\",\"policy_uri\":\"http://trust-anchor.org:8000/en/website/legal-information\",\"logo_uri\":\"http://trust-anchor.org:8000/static/svg/spid-logo-c-lb.svg\",\"federation_list_endpoint\":\"http://trust-anchor.org:8000/list\"}},\"trust_mark_issuers\":{\"https://www.spid.gov.it/certification/rp/public\":[\"https://registry.spid.agid.gov.it\",\"https://public.intermediary.spid.it\"],\"https://www.spid.gov.it/certification/rp/private\":[\"https://registry.spid.agid.gov.it\",\"https://private.other.intermediary.it\"],\"https://sgd.aa.it/onboarding\":[\"https://sgd.aa.it\"]},\"constraints\":{\"max_path_length\":1},\"new\":\"valuenew\"}",
                dop.getAPI().jwt.payload);
    }

    @Test
    public void test_add_json_jwt_null() throws ParsingException {
        String input =
                "{\n"
                        + "    \"from\": \"body\",\n"
                        + "    \"type\": \"jwt\",\n"
                        + "    \"decode regex\": \"[^\\\\n\\\\r]*\",\n"
                        + "    \"edits\": [\n"
                        + "        {\n"
                        + "            \"jwt from\": \"payload\",\n"
                        + "            \"jwt add\": \"$\",\n"
                        + "            \"key\": \"new\",\n"
                        + "            \"value\": \"\"\n"
                        + "        }\n"
                        + "    ]\n"
                        + "}";

        DecodeOperation dop = new DecodeOperation(new JSONObject(input));
        dop.loader(new Operation_API(DecodeOperation_Test.get_test_message_with_jwt(), false));

        dop.execute(null);
        assertTrue(dop.editOperations.get(0).getResult());

        assertEquals(
                "{\"exp\":1710327846,\"iat\":1710325866,\"iss\":\"http://trust-anchor.org:8000\",\"sub\":\"http://trust-anchor.org:8000\",\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"n\":\"o8IolRjZlkzct-48rhrVlTnYU1pkMbVJD-DU05oMS9RVGrsFypg98m-Kw4H4qNPyQVx2OQORi-xShgk7HU-gK_2pVguYkv06FajL_edEAqqsqt_74Qf2WLRC5pfJG_z9OPzY8JGyk-z3SbeHN_BXKI8GY5E4WU2SstmQ9fyL4CxtRfjUia8limTC_3MOpT3zi5nr03jfbjpnjga51qXurxnlzc3a_xjk5RAApKxUvNwhJ275M0CmB99DjPwF6BLvUgJqgyCpUOn36LOhI4FquVqhqhiwKlMmiMe3yy0yNQ7FXBWxjzhexbpyc3Vu7zFIHPAcC4UyIQhc3waEj2viXw\",\"e\":\"AQAB\",\"kid\":\"BXvfrlnhAMuHR07ajUmAcBRQcSzmw0c_RAgJnpS-9WQ\"}]},\"metadata\":{\"federation_entity\":{\"contacts\":[\"ops@localhost\"],\"federation_fetch_endpoint\":\"http://trust-anchor.org:8000/fetch\",\"federation_resolve_endpoint\":\"http://trust-anchor.org:8000/resolve\",\"federation_trust_mark_status_endpoint\":\"http://trust-anchor.org:8000/trust_mark_status\",\"homepage_uri\":\"http://trust-anchor.org:8000\",\"organization_name\":\"example TA\",\"policy_uri\":\"http://trust-anchor.org:8000/en/website/legal-information\",\"logo_uri\":\"http://trust-anchor.org:8000/static/svg/spid-logo-c-lb.svg\",\"federation_list_endpoint\":\"http://trust-anchor.org:8000/list\"}},\"trust_mark_issuers\":{\"https://www.spid.gov.it/certification/rp/public\":[\"https://registry.spid.agid.gov.it\",\"https://public.intermediary.spid.it\"],\"https://www.spid.gov.it/certification/rp/private\":[\"https://registry.spid.agid.gov.it\",\"https://private.other.intermediary.it\"],\"https://sgd.aa.it/onboarding\":[\"https://sgd.aa.it\"]},\"constraints\":{\"max_path_length\":1},\"new\":null}",
                dop.getAPI().jwt.payload);
    }
}
