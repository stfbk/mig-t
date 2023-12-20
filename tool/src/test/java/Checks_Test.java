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
                "    \"pagePic\": \"http://example.com/content.jpg\",\n" +
                "    \"entry\": [123, \"abc\",\"cde\"],\n" +
                "    \"imaninteger\": 123,\n" +
                "    \"imafloat\": 123.321,\n" +
                "  },\n" +
                "  \"posts\": [\n" +
                "    {\n" +
                "      \"post_id\": \"123456789012_123456789012\",\n" +
                "      \"actor_id\": \"1234567890\",\n" +
                "      \"picOfPersonWhoPosted\": \"http://example.com/photo.jpg\",\n" +
                "      \"nameOfPersonWhoPosted\": \"Jane Doe\",\n" +
                "      \"message\": \"Sounds cool. Can't wait to see it!\",\n" +
                "      \"likesCount\": \"2\",\n" +
                "      \"comments\": [\"abc\",\"cde\"],\n" +
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

    @Test
    @DisplayName("check")
    void test_check_json_string_contains_elem() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.entry\",\n" +
                "        \"contains\": [\"123\"]\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_string_not_contains_elem_wrong() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.entry\",\n" +
                "        \"not contains\": [\"123\"]\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_string_not_contains_elem() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.entry\",\n" +
                "        \"not contains\": [\"aaa\"]\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_array_is_subset_of_ok() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.entry\",\n" +
                "        \"is subset of\": [\"123\", \"abc\",\"cde\", \"altro\"]\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_array_is_subset_of_wrong() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.entry\",\n" +
                "        \"is subset of\": [\"123\", \"abc\",\"aaa\", \"altro\"]\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_matches_regex() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pagePic\",\n" +
                "        \"matches regex\": \"example\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_matches_regex_wrong() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pagePic\",\n" +
                "        \"matches regex\": \"exampsle\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_not_matches_regex() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pagePic\",\n" +
                "        \"not matches regex\": \"exampsle\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertTrue(c.getResult());
    }

    @Test
    @DisplayName("check")
    void test_check_json_not_matches_regex_wrong() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.pagePic\",\n" +
                "        \"not matches regex\": \"example\"\n" +
                "}";

        Check c = initCheck_json(check_str);
        c.execute(new ArrayList<Var>());
        assertFalse(c.getResult());
    }

    @Test
    void test_check_json_schema_validation_ok() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.imaninteger\",\n" +
                "        \"json schema compliant\": \"{\\\"type\\\":\\\"integer\\\"}\" " +
                "}";

        Check c = initCheck_json(check_str);

        c.execute(new ArrayList<>());
        assertTrue(c.getResult());
    }

    @Test
    void test_check_json_schema_validation_wrong() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.imaninteger\",\n" +
                "        \"json schema compliant\": \"{\\\"type\\\":\\\"string\\\"}\" " +
                "}";

        Check c = initCheck_json(check_str);

        c.execute(new ArrayList<>());
        assertFalse(c.getResult());
    }

    @Test
    void test_check_json_schema_validation_wrong_schema() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.imaninteger\",\n" +
                "        \"json schema compliant\": \"wrongschema\" " +
                "}";

        Check c = initCheck_json(check_str);
        try {
            c.execute(new ArrayList<>());
        } catch (RuntimeException | ParsingException e) {
            assertEquals(1,1);
            return;
        }
        assertEquals(1,0);
    }
    @Test
    void test_print_extended() throws ParsingException {
        String check_str = "{\n" +
                "        \"in\": \"header\",\n" +
                "        \"check\": \"$.pageInfo.imaninteger\",\n" +
                "        \"json schema compliant\": \"wrongschema\" " +
                "}";

        Check c = initCheck_json(check_str);

        System.out.println(c.toStringExtended());
    }
}
