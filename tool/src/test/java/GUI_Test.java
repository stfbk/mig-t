import migt.ParsingException;
import migt.Session;
import migt.Utils;
import org.json.JSONObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class GUI_Test {

    @Test
    @DisplayName("ParsingRawSessionAction test")
    void test_batchPassivesFromSession() throws ParsingException {
        List<migt.Test> tests = new ArrayList<>();

        for (int i = 0; i < 8; i++) {
            migt.Test t1 = new migt.Test();
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

        HashMap<String, List<migt.Test>> hm = Utils.batchPassivesFromSession(tests);

        assertEquals(3, hm.get("1").size());
        assertEquals(2, hm.get("2").size());
        assertEquals(2, hm.get("3").size());
        assertEquals(1, hm.get("4").size());
    }
}