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

import org.json.JSONArray;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.HTTPReqRes;
import org.zaproxy.addon.migt.ParsingException;
import org.zaproxy.addon.migt.Var;

public class Var_Test {

    @Test
    void test_var_string() throws ParsingException {
        Var v = new Var("prova", "provona");

        assertEquals(v.name, "prova");
        assertEquals(v.value, "provona");
        assertEquals(v.getType(), Var.VarType.STRING);
    }

    @Test
    void test_var_message() throws ParsingException {

        HTTPReqRes message = HTTPReqRes_Test.initMessage_ok();

        Var v = new Var("prova", message.getRequest());

        assertEquals(v.name, "prova");
        assertEquals(v.value, message.getRequest());
        assertEquals(v.get_value_message(), message.getRequest());
        assertEquals(v.getType(), Var.VarType.MESSAGE);
    }

    @Test
    void test_var_json_array() {
        JSONArray ja = new JSONArray("[\"first\", \"second\"]");

        Var v = new Var("var1", ja.toList().toArray());

        assertEquals(v.name, "var1");
        assertEquals(((String[]) v.value)[0], ja.get(0));
        assertEquals(((String[]) v.value)[1], ja.get(1));
        assertEquals(v.getType(), Var.VarType.STRING_ARRAY);
    }
}
