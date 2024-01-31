import migt.EditOperation;
import migt.HTTPReqRes;
import migt.Operation_API;
import migt.ParsingException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EditOperation_test {
    HTTPReqRes message = HTTPReqRes_Test.initMessage_ok();
    HTTPReqRes message_w_body;

    @Test
    public void test_encode_url_param() throws ParsingException {
        String input = "{\"from\": \"url\", \"encode\": \"format\"," + "\"encodings\": [\"base64\"]}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("anNvbg==", res.message.getUrlParam("format"));
    }

    @Test
    public void test_encode_head_param() throws ParsingException {
        String input = "{\"from\": \"head\", \"encode\": \"Host\"," + "\"encodings\": [\"base64\"]}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("cGxheS5nb29nbGUuY29t", res.message.getHeadParam(true, "Host"));
    }

    @Test
    public void test_encode_body_param() throws ParsingException {
        String input = "{\"from\": \"body\", \"encode\": \".*\"," + "\"encodings\": [\"base64\"]}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("Ym9keWNvbnRlbnQ=", new String(res.message.getBody(true)));
    }

    @Test
    public void test_edit_url_regex() throws ParsingException {
        String input = "{\"from\": \"url\", \"edit regex\": \"format=json\"," + "\"value\": \"test=testone\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("testone", res.message.getUrlParam("test"));
    }

    @Test
    public void test_edit_head_regex() throws ParsingException {
        String input = "{\"from\": \"head\", \"edit regex\": \"Host:\"," + "\"value\": \"Hosted:\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("play.google.com", res.message.getHeadParam(true, "Hosted"));
    }

    @Test
    public void test_edit_body_regex() throws ParsingException {
        String input = "{\"from\": \"body\", \"edit regex\": \"ent\"," + "\"value\": \"123\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("bodycont123", new String(res.message.getBody(true)));
    }

    @Test
    public void test_add_url_param() throws ParsingException {
        String input = "{\"from\": \"url\", \"add\": \"codechallenge\"," + "\"value\": \"12345\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("12345", res.message.getUrlParam("codechallenge"));
    }

    @Test
    public void test_add_url_param_already_present() throws ParsingException {
        String input = "{\"from\": \"url\", \"add\": \"authuser\"," + "\"value\": \"1\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("01", res.message.getUrlParam("authuser"));
    }

    @Test
    public void test_add_head_param() throws ParsingException {
        String input = "{\"from\": \"head\", \"add\": \"Magicheader\"," + "\"value\": \"123123\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("123123", res.message.getHeadParam(true, "Magicheader"));
    }

    @Test
    public void test_add_head_param_already_present() throws ParsingException {
        String input = "{\"from\": \"head\", \"add\": \"Accept\"," + "\"value\": \"1\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("*/*1", res.message.getHeadParam(true, "Accept"));
    }

    @Test
    public void test_add_body() throws ParsingException {
        String input = "{\"from\": \"body\", \"add\": \"anything\"," + "\"value\": \"&appended\"}";
        EditOperation eop = new EditOperation(new JSONObject(input));
        Operation_API api = new Operation_API(message, true);

        eop.setAPI(api);
        eop.execute(null);
        assertTrue(eop.getResult());
        Operation_API res = (Operation_API) eop.exporter();
        assertEquals("bodycontent&appended",
                new String(res.message.getBody(true)));
    }
}
