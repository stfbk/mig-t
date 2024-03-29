import migt.ParsingException;
import migt.SessionOperation;
import migt.SessionTrackAction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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

            s = new SessionTrackAction("click | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |");
            assertEquals(SessionOperation.SessAction.CLICK, s.action);
            assertEquals("xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1]", s.elem);
            assertEquals("xpath", s.elem_type);
            assertEquals("/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1]", s.elem_source);
            assertEquals("click | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |", s.toString());

            s = new SessionTrackAction("type | id=login | folafo9046@eoscast.com");
            assertEquals(SessionOperation.SessAction.TYPE, s.action);
            assertEquals("id=login", s.elem);
            assertEquals("id", s.elem_type);
            assertEquals("login", s.elem_source);
            assertEquals("folafo9046@eoscast.com", s.content);
            assertEquals("type | id=login | folafo9046@eoscast.com", s.toString());

            s = new SessionTrackAction("wait | 3000 |");
            assertEquals("wait | 3000 |", s.toString());

            s = new SessionTrackAction("equals | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |");
            assertEquals(SessionOperation.SessAction.EQUALS, s.action);
            assertEquals("equals | xpath=/html/body/div[1]/div[3]/div/div[5]/div[1]/span[1] |", s.toString());
        } catch (ParsingException e) {
            assertEquals(1, 0);
        }
    }

    @Test
    @DisplayName("Test Action assert")
    void testActionAsserts() throws ParsingException {
        SessionTrackAction s = new SessionTrackAction();
        String in = "";

        in = "assert clickable | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.action, SessionOperation.SessAction.ASSERT_CLICKABLE);
        assertEquals(in, s.toString());

        s = new SessionTrackAction();
        in = "assert not clickable | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.toString(), in);

        s = new SessionTrackAction();
        in = "assert visible | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.toString(), in);

        s = new SessionTrackAction();
        in = "assert not visible | xpath=/html/body/div[1]/div[2]/div/div[2]/div/div/div/div[2]/div[2]/form/div[6]/div/div[3]/div/div[2]/div[1]/a |";
        s.parse_raw_action(in);
        assertEquals(s.toString(), in);
    }
}
