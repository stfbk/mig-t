import burp.ParsingException;
import burp.SessionOperation;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

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