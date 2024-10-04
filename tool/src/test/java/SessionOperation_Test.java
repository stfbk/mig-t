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

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.migt.ParsingException;
import org.zaproxy.addon.migt.SessionOperation;

public class SessionOperation_Test {

    @Test
    @DisplayName("ParsingRawSessionAction test")
    void test_parseRawSessionAction() throws ParsingException {
        List<Object> l = SessionOperation.parseRange("[something, prova2]");

        assertTrue((boolean) l.get(0));
        assertTrue((boolean) l.get(1));
        assertEquals(l.get(2), "something");
        assertEquals(l.get(3), "prova2");

        l = SessionOperation.parseRange("( something, prova2)");

        assertFalse((boolean) l.get(0));
        assertFalse((boolean) l.get(1));
        assertEquals(l.get(2), "something");
        assertEquals(l.get(3), "prova2");
    }
}
