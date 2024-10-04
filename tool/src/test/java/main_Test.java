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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.ParsingException;
import org.zaproxy.addon.migt.Session;
import org.zaproxy.addon.migt.Tools;

public class main_Test {

    @Test
    @DisplayName("ParsingRawSessionAction test")
    void test_batchPassivesFromSession() throws ParsingException {
        List<org.zaproxy.addon.migt.Test> tests = new ArrayList<>();

        for (int i = 0; i < 8; i++) {
            org.zaproxy.addon.migt.Test t1 = new org.zaproxy.addon.migt.Test();
            t1.sessions.add(new Session());
            tests.add(t1);
        }

        tests.get(0).sessions.get(0).name = "1";
        tests.get(1).sessions.get(0).name = "2";
        tests.get(2).sessions.get(0).name = "2";
        tests.get(3).sessions.get(0).name = "3";
        tests.get(4).sessions.get(0).name = "1";
        tests.get(5).sessions.get(0).name = "3";
        tests.get(6).sessions.get(0).name = "4";
        tests.get(7).sessions.get(0).name = "1";

        HashMap<String, List<org.zaproxy.addon.migt.Test>> hm =
                Tools.batchPassivesFromSession(tests);

        assertEquals(3, hm.get("1").size());
        assertEquals(2, hm.get("2").size());
        assertEquals(2, hm.get("3").size());
        assertEquals(1, hm.get("4").size());
    }
}
