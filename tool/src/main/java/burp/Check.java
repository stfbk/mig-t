package burp;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Check Object class. This object is used in Operations to check that a parameter or some text is in as specified.
 *
 * @author Matteo Bitussi
 */
public class Check {
    String what; // what to search
    Utils.CheckOps op; // the check operations
    Utils.MessageSection in; // the section over which to search
    String op_val;
    boolean isParamCheck = false; // specifies if what is declared in what is a parameter name

    Utils.ContentType contentType; // The content on which the check should work on

    /**
     * Execute the check if it is http
     *
     * @param message
     * @param helpers
     * @param isRequest
     * @return
     * @throws ParsingException
     */
    private boolean execute_http(HTTPReqRes message,
                                 IExtensionHelpers helpers,
                                 boolean isRequest) throws ParsingException {
        String msg_str = "";
        IRequestInfo req_info = null;
        IResponseInfo res_info = null;
        if (isRequest) req_info = helpers.analyzeRequest(message.getRequest());
        if (!isRequest) res_info = helpers.analyzeResponse(message.getResponse());
        if (this.in == null) {
            throw new ParsingException("from tag in checks is null");
        }
        switch (this.in) {
            case URL:
                if (!isRequest) {
                    throw new ParsingException("Searching URL in response");
                }
                msg_str = req_info.getHeaders().get(0);
                break;
            case BODY:
                if (isRequest) {
                    int offset = req_info.getBodyOffset();
                    byte[] body = Arrays.copyOfRange(message.getRequest(), offset, message.getRequest().length);
                    msg_str = new String(body);
                } else {
                    int offset = res_info.getBodyOffset();
                    byte[] body = Arrays.copyOfRange(message.getResponse(), offset, message.getResponse().length);
                    msg_str = new String(body);
                }
                break;
            case HEAD:
                if (isRequest) {
                    int offset = req_info.getBodyOffset();
                    byte[] head = Arrays.copyOfRange(message.getRequest(), 0, offset);
                    msg_str = new String(head);
                } else {
                    int offset = res_info.getBodyOffset();
                    byte[] head = Arrays.copyOfRange(message.getResponse(), 0, offset);
                    msg_str = new String(head);
                }
                break;
            default:
                System.err.println("no valid \"in\" specified in check");
                return false;
        }

        if (msg_str.length() == 0) {
            return false;
        }

        if (this.isParamCheck) {
            try {
                Pattern p = this.in == Utils.MessageSection.URL ?
                        Pattern.compile("(?<=[?&]" + this.what + "=)[^\\n&]*") :
                        Pattern.compile("(?<=" + this.what + ":\\s?)[^\\n]*");
                Matcher m = p.matcher(msg_str);

                String val = "";
                if (m.find()) {
                    val = m.group();
                } else {
                    return false;
                }

                if (this.op == null && val.length() != 0) {
                    // if it passed all the splits without errors, the param is present, but no checks are specified
                    // so result is true
                    return true;
                }

                switch (this.op) {
                    case IS:
                        if (!this.op_val.equals(val)) {
                            return false;
                        }
                        break;
                    case IS_NOT:
                        if (this.op_val.equals(val)) {
                            return false;
                        }
                        break;
                    case CONTAINS:
                        if (!val.contains(this.op_val)) {
                            return false;
                        }
                        break;
                    case NOT_CONTAINS:
                        if (val.contains(this.op_val)) {
                            return false;
                        }
                        break;
                    case IS_PRESENT:
                        return true; // if it gets to this, the searched param is already found
                    case IS_NOT_PRESENT:
                        return false;
                }
            } catch (ArrayIndexOutOfBoundsException e) {
                //e.printStackTrace();
                if (this.op != null) {
                    if (this.op != Utils.CheckOps.IS_NOT_PRESENT) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        } else {
            if (!msg_str.contains(this.what)) {
                if (this.op != null) {
                    return this.op == Utils.CheckOps.IS_NOT_PRESENT;
                } else {
                    return false;
                }
            } else {
                if (this.op != null) {
                    return this.op != Utils.CheckOps.IS_NOT_PRESENT;
                }
            }
        }
        return true;
    }

    private boolean execute_json(HTTPReqRes message,
                                 IExtensionHelpers helpers,
                                 boolean isRequest) throws ParsingException {
        return true;
        // https://github.com/json-path/JsonPath
        // TODO
        //String something = JsonPath.read(json, "$.store.book[*].author");

        //JSONParser jsonParser = new JSONParser();
    }

    /**
     * Executes the given check
     *
     * @param message
     * @param helpers
     * @param isRequest
     * @return the result of the check (passed or not passed)
     */
    public boolean execute(HTTPReqRes message,
                           IExtensionHelpers helpers,
                           boolean isRequest) throws ParsingException {
        switch (contentType) {
            case HTTP:
                return execute_http(message, helpers, isRequest);
            case JSON:
                return execute_json(message, helpers, isRequest);
            default:
                throw new ParsingException("invalid content type + " + contentType);
        }
    }

    public void setWhat(String what) {
        this.what = what;
    }

    public void setOp(Utils.CheckOps op) {
        this.op = op;
    }

    @Override
    public String toString() {
        return "check: " + what + (op == null ? "" : " " + op + ": " + op_val);
    }
}
