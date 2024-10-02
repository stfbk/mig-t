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
import org.zaproxy.addon.migt.HTTPReqRes;
import org.zaproxy.addon.migt.MessageOperation;
import org.zaproxy.addon.migt.Operation_API;
import org.zaproxy.addon.migt.ParsingException;

public class MessageOeration_Test {

    @Test
    void test_save_head_param() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();

        String msg_op_txt =
                "{\n"
                        + "            \"from\": \"head\",\n"
                        + "            \"save\": \"Host\",\n"
                        + "            \"as\": \"var_name\"\n"
                        + "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("play.google.com", op_api.vars.get(0).value);
    }

    @Test
    void test_save_head_regex() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();

        String msg_op_txt =
                "{\n"
                        + "            \"from\": \"head\",\n"
                        + "            \"save match\": \"Host:[^\\n\\r]*\",\n"
                        + "            \"as\": \"var_name\"\n"
                        + "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("Host: play.google.com", op_api.vars.get(0).value);
    }

    @Test
    void test_save_url_param() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();
        String msg_op_txt =
                "{\n"
                        + "            \"from\": \"url\",\n"
                        + "            \"save\": \"format\",\n"
                        + "            \"as\": \"var_name\"\n"
                        + "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("json", op_api.vars.get(0).value);
    }

    @Test
    void test_save_url_param_no_decode() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();
        String msg_op_txt =
                "{\n"
                        + "            \"from\": \"url\",\n"
                        + "            \"save\": \"paramwithspace\",\n"
                        + "            \"as\": \"var_name\",\n"
                        + "            \"url decode\": false"
                        + "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("first+last", op_api.vars.get(0).value);
    }

    @Test
    void test_save_url_regex() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();
        String msg_op_txt =
                "{\n"
                        + "            \"from\": \"url\",\n"
                        + "            \"save match\": \"format=[^&\\n\\r]*\",\n"
                        + "            \"as\": \"var_name\"\n"
                        + "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("format=json", op_api.vars.get(0).value);
    }

    @Test
    void test_save_body_regex() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();
        msg.setBody(true, "asdasdasd");
        String msg_op_txt =
                "{\n"
                        + "            \"from\": \"body\",\n"
                        + "            \"save\": \"asdasdasd\","
                        + "            \"as\": \"var_name\"\n"
                        + "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("asdasdasd", op_api.vars.get(0).value);
    }
}
