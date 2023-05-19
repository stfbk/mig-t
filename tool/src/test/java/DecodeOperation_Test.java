import migt.DecodeOperation;
import migt.ParsingException;
import migt.Utils;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DecodeOperation_Test {
    String input = "{\n" +
            "    \"from\": \"url\",\n" +
            "    \"encodings\": [\"jwt\"],\n" +
            "    \"decode param\": \"asd\",\n" +
            "    \"decode operations\": [\n" +
            "      {\n" +
            "        \"from\": \"jwt header\",\n" +
            "        \"encodings\": [\"jwt\"],\n" +
            "        \"decode param\": \"$.something\"\n" +
            "      }\n" +
            "    ]\n" +
            "  }";

    @Test
    void test_parse() throws ParsingException {
        DecodeOperation dop = new DecodeOperation(new JSONObject(input));

        assertEquals(Utils.DecodeOperationFrom.URL, dop.from);
        assertEquals(Utils.Encoding.JWT, dop.encodings.get(0));
        assertEquals("asd", dop.decode_target);
        assertTrue(dop.decodeOperations.size() == 1);

        DecodeOperation child_dop = dop.decodeOperations.get(0);
        assertEquals(Utils.DecodeOperationFrom.JWT_HEADER, child_dop.from);
        assertEquals(Utils.Encoding.JWT, child_dop.encodings.get(0));
        assertEquals("$.something", child_dop.decode_target);
    }
}
