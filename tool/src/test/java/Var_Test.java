import migt.HTTPReqRes;
import migt.ParsingException;
import migt.Var;
import org.json.JSONArray;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
