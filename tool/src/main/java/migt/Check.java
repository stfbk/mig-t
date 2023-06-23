package migt;

import burp.IExtensionHelpers;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.jayway.jsonpath.JsonPath;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static migt.Utils.CheckOps.IS_NOT_PRESENT;

/**
 * Check Object class. This object is used in Operations to check that a parameter or some text is in as specified.
 *
 * @author Matteo Bitussi
 */
public class Check extends Module {
    String what; // what to search
    Utils.CheckOps op; // the check operations
    Utils.CheckIn in; // the section over which to search
    String op_val;
    boolean isParamCheck = false; // specifies if what is declared in what is a parameter name

    Utils.ContentType contentType; // The content on which the check should work on

    public Check() {

    }

    /**
     * Instantiate a new Check object given its parsed JSONObject
     *
     * @param json_check the check as JSONObject
     * @throws ParsingException
     */
    public Check(JSONObject json_check) throws ParsingException {
        Iterator<String> keys = json_check.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            switch (key) {
                case "in":
                    if (key.equals("in")) {
                        this.in = Utils.CheckIn.fromString(json_check.getString("in"));
                    }
                case "check param":
                    if (key.equals("check param")) {
                        this.isParamCheck = true;
                        this.setWhat(json_check.getString("check param"));
                        break;
                    }
                case "check":
                    if (key.equals("check")) {
                        this.setWhat(json_check.getString("check"));
                        break;
                    }
                case "is":
                    if (key.equals("is")) {
                        this.setOp(Utils.CheckOps.IS);
                        this.op_val = json_check.getString("is");
                        break;
                    }
                case "is not":
                    if (key.equals("is not")) {
                        this.setOp(Utils.CheckOps.IS_NOT);
                        this.op_val = json_check.getString("is not");
                        break;
                    }
                case "contains":
                    if (key.equals("contains")) {
                        this.setOp(Utils.CheckOps.CONTAINS);
                        this.op_val = json_check.getString("contains");
                        break;
                    }
                case "not contains":
                    if (key.equals("not contains")) {
                        this.setOp(Utils.CheckOps.NOT_CONTAINS);
                        this.op_val = json_check.getString("not contains");
                        break;
                    }
                case "is present":
                    if (key.equals("is present")) {
                        this.op = json_check.getBoolean("is present") ? Utils.CheckOps.IS_PRESENT :
                                IS_NOT_PRESENT;
                        this.op_val = json_check.getBoolean("is present") ?
                                "is present" : "is not present";
                    }
            }
        }
    }

    public void loader(DecodeOperation_API api) {
        this.imported_api = api;
    }

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
                msg_str = message.getUrlHeader();
                break;
            case BODY:
                msg_str = new String(message.getBody(isRequest), StandardCharsets.UTF_8);
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
                Pattern p = this.in == Utils.CheckIn.URL ?
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
                    if (this.op != IS_NOT_PRESENT) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        } else {
            if (!msg_str.contains(this.what)) {
                if (this.op != null) {
                    return this.op == IS_NOT_PRESENT;
                } else {
                    return false;
                }
            } else {
                if (this.op != null) {
                    return this.op != IS_NOT_PRESENT;
                }
            }
        }
        return true;
    }

    /**
     * Execute the json version of the check
     *
     * @return the result of the execution //TODO: change to API
     * @throws ParsingException
     */
    private boolean execute_json() throws ParsingException {
        DecodeOperation_API tmp = ((DecodeOperation_API) this.imported_api);

        String j = "";

        switch (in) {
            case JWT_HEADER: {
                j = tmp.jwt_header;
                break;
            }
            case JWT_PAYLOAD: {
                j = tmp.jwt_payload;
                break;
            }
            case JWT_SIGNATURE: {
                j = tmp.jwt_signature;
                break;
            }
        }

        String found = "";
        // https://github.com/json-path/JsonPath
        try {
            found = JsonPath.read(j, what);
        } catch (com.jayway.jsonpath.PathNotFoundException e) {
            applicable = true;
            return op == IS_NOT_PRESENT;
        }

        applicable = true; // at this point the path has been found so the check is applicable

        if (isParamCheck) {
            throw new ParsingException("Cannot execute a 'check param' in a json, please use 'check'");
        }

        switch (op) {
            case IS:
                return op_val.equals(found);
            case IS_NOT:
                return !op_val.equals(found);
            case CONTAINS:
                return found.contains(op_val);
            case NOT_CONTAINS:
                return !found.contains(op_val);
            case IS_PRESENT:
                return !found.equals("");
            case IS_NOT_PRESENT:
                return found.equals("");
        }

        return false;
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
        //TODO: migrate to api
        result = execute_http(message, helpers, isRequest);
        return result;
        // TODO REMOVE CONTENT TYPE
    }

    public void execute() throws ParsingException {
        switch (((DecodeOperation_API) imported_api).type) {
            case JWT:
                result = execute_json();
                break;
            case NONE:
                break;
            //TODO
            case XML:
                //TODO
                break;
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
