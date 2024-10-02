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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.ParsingException;
import org.zaproxy.addon.migt.SessionOperation;
import org.zaproxy.addon.migt.SessionTrackAction;

public class SessionTrackAction_Test {

    @Test
    @DisplayName("ParsingRawSessionAction test")
    void test_parseRawSessionAction() {
        SessionTrackAction s = new SessionTrackAction();

        try {
            s.parse_raw_action("open | https://www.facebook.com/ |");
            assertEquals(SessionOperation.SessAction.OPEN, s.action);
            assertEquals("https://www.facebook.com/", s.elem);
            assertEquals("open | https://www.facebook.com/ |", s.toString());

            s =
                    new SessionTrackAction(
                            "click | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |");
            assertEquals(SessionOperation.SessAction.CLICK, s.action);
            assertEquals("xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1]", s.elem);
            assertEquals("xpath", s.elem_type);
            assertEquals("/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1]", s.elem_source);
            assertEquals(
                    "click | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |",
                    s.toString());

            s = new SessionTrackAction("type | id=login | folafo9046@eoscast.com");
            assertEquals(SessionOperation.SessAction.TYPE, s.action);
            assertEquals("id=login", s.elem);
            assertEquals("id", s.elem_type);
            assertEquals("login", s.elem_source);
            assertEquals("folafo9046@eoscast.com", s.content);
            assertEquals("type | id=login | folafo9046@eoscast.com", s.toString());

            s = new SessionTrackAction("wait | 3000 |");
            assertEquals("wait | 3000 |", s.toString());

            s =
                    new SessionTrackAction(
                            "equals | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |");
            assertEquals(SessionOperation.SessAction.EQUALS, s.action);
            assertEquals(
                    "equals | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |",
                    s.toString());
        } catch (ParsingException e) {
            assertEquals(1, 0);
        }
    }

    @Test
    @DisplayName("Test Action assert")
    void testActionAsserts() throws ParsingException {
        SessionTrackAction s = new SessionTrackAction();
        String in = "";

        in =
                "assert clickable | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.action, SessionOperation.SessAction.ASSERT_CLICKABLE);
        assertEquals(in, s.toString());

        s = new SessionTrackAction();
        in =
                "assert not clickable | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.toString(), in);

        s = new SessionTrackAction();
        in =
                "assert visible | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.toString(), in);

        s = new SessionTrackAction();
        in =
                "assert not visible | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.toString(), in);
    }
}
