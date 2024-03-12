import migt.DecodeOperation;
import migt.ParsingException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DecodeOperation_Test {
    String input = "{\n" +
            "    \"from\": \"url\",\n" +
            "    \"type\": \"jwt\",\n" +
            "    \"decode param\": \"asd\",\n" +
            "    \"decode operations\": [\n" +
            "      {\n" +
            "        \"from\": \"jwt header\",\n" +
            "        \"type\": \"jwt\",\n" +
            "        \"decode param\": \"$.something\"\n" +
            "      }\n" +
            "    ]\n" +
            "  }";

    String input_w_checks = "{\n" +
            "                \"from\": \"body\",\n" +
            "                \"decode param\": \"(?<=authz_request_object=)[^$\\n& ]*\",\n" +
            "                \"type\": \"jwt\",\n" +
            "                \"checks\": [\n" +
            "                  {\n" +
            "                    \"in\": \"payload\",\n" +
            "                    \"check\": \"$.scope\",\n" +
            "                    \"is\": \"openid\"\n" +
            "                  }\n" +
            "                ]\n" +
            "              }";

    String input_w_edits = "{\n" +
            "                \"from\": \"body\",\n" +
            "                \"decode param\": \"(?<=authz_request_object=)[^$\\n& ]*\",\n" +
            "                \"type\": \"jwt\",\n" +
            "                \"edits\": [\n" +
            "                  {\n" +
            "                    \"jwt from\": \"payload\",\n" +
            "                    \"jwt edit\": \"$.scope\",\n" +
            "                    \"value\": \"qualcosaltro\"\n" +
            "                  }\n" +
            "                ]\n" +
            "              }";

    String input_w_edits_save = "{\n" +
            "                \"from\": \"body\",\n" +
            "                \"decode param\": \"(?<=authz_request_object=)[^$\\n& ]*\",\n" +
            "                \"type\": \"jwt\",\n" +
            "                \"edits\": [\n" +
            "                  {\n" +
            "                    \"jwt from\": \"payload\",\n" +
            "                    \"jwt save\": \"$.scope\",\n" +
            "                    \"as\": \"varname\"\n" +
            "                  }\n" +
            "                ]\n" +
            "              }";

    @Test
    void test_parse() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input));

        assertEquals(DecodeOperation.DecodeOperationFrom.URL, dop.from);
        assertEquals("asd", dop.decode_target);
        assertEquals(1, dop.decodeOperations.size());

        DecodeOperation child_dop = dop.decodeOperations.get(0);
        assertEquals(DecodeOperation.DecodeOperationFrom.JWT_HEADER, child_dop.from);
        assertEquals("$.something", child_dop.decode_target);
    }

    @Test
    void test_parse_w_checks() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_checks));

        assertEquals(DecodeOperation.DecodeOperationFrom.BODY, dop.from);
        assertEquals(1, dop.checks.size());

    }

    @Test
    void test_parse_w_edits() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_edits));

        assertEquals(1, dop.editOperations.size());
    }

    @Test
    void test_parse_w_edits_save() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_edits_save));

        assertEquals(1, dop.editOperations.size());
    }

    @Test
    void test_print_extended() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input_w_edits_save));
        System.out.println(dop.toStringExtended());
    }
}
