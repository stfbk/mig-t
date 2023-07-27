import migt.*;
import org.json.JSONObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class Checks_Test {

    public Check initCheck_json(String check_str) throws ParsingException {
        String input = "{\n" +
                "  \"pageInfo\": {\n" +
                "    \"pageName\": \"abc\",\n" +
                "    \"pagePic\": \"http://example.com/content.jpg\"\n" +
                "  },\n" +
                "  \"posts\": [\n" +
                "    {\n" +
                "      \"post_id\": \"123456789012_123456789012\",\n" +
                "      \"actor_id\": \"1234567890\",\n" +
                "      \"picOfPersonWhoPosted\": \"http://example.com/photo.jpg\",\n" +
                "      \"nameOfPersonWhoPosted\": \"Jane Doe\",\n" +
                "      \"message\": \"Sounds cool. Can't wait to see it!\",\n" +
                "      \"likesCount\": \"2\",\n" +
                "      \"comments\": [],\n" +
                "      \"timeOfPost\": \"1234567890\"\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        Check c = new Check(new JSONObject(check_str));

        DecodeOperation_API dopapi = new DecodeOperation_API();
        dopapi.type = DecodeOperation.DecodeOpType.JWT;
        dopapi.jwt.header = input;
        c.loader(dopapi);

        return c;
    }

    @Test
    @DisplayName("check")
    void test_check() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pageName\",\n" +
                "        \"is\": \"abc\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_is_not() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pageName\",\n" +
                "        \"is\": \"notabc\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_contains() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pageName\",\n" +
                "        \"contains\": \"abc\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_not_contains() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pageName\",\n" +
                "        \"not contains\": \"abc\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_not_found() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.notexisting\",\n" +
                "        \"is\": \"abc\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_not_present() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.notexisting\",\n" +
                "        \"is present\": \"false\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_not_present_wrong() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.notexisting\",\n" +
                "        \"is present\": \"true\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_is_inside_list() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.posts[0].actor_id\",\n" +
                "        \"is\": \"1234567890\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_set_result() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.posts[0].actor_id\",\n" +
                "        \"is\": \"1234567890\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());

        DecodeOperation dop = new DecodeOperation();
        dop.setResult(c);

        assertTrue(dop.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_use_variable() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"use variable\": true,\n" +
                "        \"check\": \"$.pageInfo.pageName\",\n" +
                "        \"is\": \"variablename\"\n" +
                "}";

        List<Var> vars = new ArrayList<Var>();
        vars.add(new Var("variablename", "abc", false));

        Check c = initCheck_json(check_str);
        c.execute(vars);
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_use_variable_wrong() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"use variable\": true,\n" +
                "        \"check\": \"$.pageInfo.pageName\",\n" +
                "        \"is\": \"variablename\"\n" +
                "}";

        List<Var> vars = new ArrayList<Var>();
        vars.add(new Var("variablename", "ac", false));

        Check c = initCheck_json(check_str);
        c.execute(vars);
        assertFalse(c.getResult());
    }
}
