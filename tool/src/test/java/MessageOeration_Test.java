import migt.HTTPReqRes;
import migt.MessageOperation;
import migt.Operation_API;
import migt.ParsingException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MessageOeration_Test {

    @Test
    void test_save_head_param() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();

        String msg_op_txt =
                "{\n" +
                        "            \"from\": \"head\",\n" +
                        "            \"save\": \"Host\",\n" +
                        "            \"as\": \"var_name\"\n" +
                        "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("play.google.com", op_api.vars.get(0).value);
    }

    @Test
    void test_save_head_regex() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();

        String msg_op_txt =
                "{\n" +
                        "            \"from\": \"head\",\n" +
                        "            \"save match\": \"Host:[^\\n\\r]*\",\n" +
                        "            \"as\": \"var_name\"\n" +
                        "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("Host: play.google.com", op_api.vars.get(0).value);
    }

    @Test
    void test_save_url_param() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();
        String msg_op_txt =
                "{\n" +
                        "            \"from\": \"url\",\n" +
                        "            \"save\": \"format\",\n" +
                        "            \"as\": \"var_name\"\n" +
                        "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("json", op_api.vars.get(0).value);
    }

    @Test
    void test_save_url_regex() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();
        String msg_op_txt =
                "{\n" +
                        "            \"from\": \"url\",\n" +
                        "            \"save match\": \"format=[^&\\n\\r]*\",\n" +
                        "            \"as\": \"var_name\"\n" +
                        "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("format=json", op_api.vars.get(0).value);
    }

    @Test
    void test_save_body_regex() throws ParsingException {
        HTTPReqRes msg = HTTPReqRes_Test.initMessage_ok();
        msg.setBody(true, "asdasdasd");
        String msg_op_txt =
                "{\n" +
                        "            \"from\": \"body\",\n" +
                        "            \"save\": \"asdasdasd\"," +
                        "            \"as\": \"var_name\"\n" +
                        "        }";

        MessageOperation mop = new MessageOperation(new JSONObject(msg_op_txt));
        Operation_API op_api = new Operation_API(msg, true);
        mop.loader(op_api);
        mop.execute();
        op_api = mop.exporter();
        assertTrue(mop.getResult());
        assertEquals("asdasdasd", op_api.vars.get(0).value);
    }
}
