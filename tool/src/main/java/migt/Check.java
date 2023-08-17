package migt;

import com.jayway.jsonpath.JsonPath;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static migt.Check.CheckOps.IS_NOT_PRESENT;

/**
 * Check Object class. This object is used in Operations to check that a parameter or some text is in as specified.
 *
 * @author Matteo Bitussi
 */
public class Check extends Module {
    String what; // what to search
    CheckOps op; // the check operations
    CheckIn in; // the section over which to search
    String op_val;
    List<String> value_list; // the eventual list of values to check between
    boolean isParamCheck; // specifies if what is declared in what is a parameter name
    String regex; // the eventual regex to use
    boolean use_variable; // if a variable name will be used in the check operation

    public Check() {
        init();
    }

    /**
     * Instantiate a new Check object given its parsed JSONObject
     *
     * @param json_check the check as JSONObject
     * @throws ParsingException if the input is not compliant with the language
     */
    public Check(JSONObject json_check) throws ParsingException {
        init();
        Iterator<String> keys = json_check.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            try {
                switch (key) {
                    case "in":
                        this.in = CheckIn.fromString(json_check.getString("in"));
                        break;
                    case "check param":
                        this.isParamCheck = true;
                        this.setWhat(json_check.getString("check param"));
                        break;
                    case "check":
                        this.setWhat(json_check.getString("check"));
                        break;
                    case "check regex":
                        regex = json_check.getString("check regex");
                        break;
                    case "use variable":
                        use_variable = json_check.getBoolean("use variable");
                        break;
                    case "is":
                        this.setOp(CheckOps.IS);
                        this.op_val = json_check.getString("is");
                        break;
                    case "is not":
                        this.setOp(CheckOps.IS_NOT);
                        this.op_val = json_check.getString("is not");
                        break;
                    case "contains":
                        this.setOp(CheckOps.CONTAINS);
                        this.op_val = json_check.getString("contains");
                        break;
                    case "not contains":
                        this.setOp(CheckOps.NOT_CONTAINS);
                        this.op_val = json_check.getString("not contains");
                        break;
                    case "is present":
                        this.op = json_check.getBoolean("is present") ? CheckOps.IS_PRESENT :
                                IS_NOT_PRESENT;
                        this.op_val = json_check.getBoolean("is present") ?
                                "is present" : "is not present";
                        break;
                    case "is in":
                        this.op = CheckOps.IS_IN;
                        JSONArray jsonArr = json_check.getJSONArray("is in");
                        Iterator<Object> it = jsonArr.iterator();

                        while (it.hasNext()) {
                            String act_enc = (String) it.next();
                            value_list.add(act_enc);
                        }
                        break;
                    case "is not in":
                        this.op = CheckOps.IS_NOT_IN;
                        JSONArray jsonArr2 = json_check.getJSONArray("is not in");
                        Iterator<Object> it2 = jsonArr2.iterator();

                        while (it2.hasNext()) {
                            String act_enc = (String) it2.next();
                            value_list.add(act_enc);
                        }
                        break;
                }
            } catch (JSONException e) {
                throw new ParsingException("error in parsing check: " + e);
            }

        }

        if (regex.equals("") && what.equals(""))
            throw new ParsingException("Error in parsing check");
    }

    public void init() {
        what = "";
        op_val = "";
        isParamCheck = false;
        regex = "";
        value_list = new ArrayList<>();
        use_variable = false;
    }

    /**
     * Loads a Decode operation's API into the check
     *
     * @param api the Decode operation's api to load
     */
    public void loader(DecodeOperation_API api) {
        this.imported_api = api;
    }

    /**
     * Loads an Operation's API into the check
     *
     * @param api the Operation's API to load
     */
    public void loader(Operation_API api) {
        this.imported_api = api;
    }

    /**
     * Executes the regex version of the check
     *
     * @param input the input content
     * @return the result of the check
     */
    private boolean execute_regex(String input) {
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(input);
        applicable = true;

        String val = "";
        if (m.find()) {
            val = m.group();
        }

        if (this.op == null) {
            // Return result based on matched or not
            return (val.length() > 0);
        } else {
            // execute op against matched value
            return do_check(val);
        }
    }

    /**
     * Execute the check over a message (in an Operation)
     *
     * @param message   the message to check
     * @param isRequest tells if the message is a request or a response
     * @return the result of the check
     * @throws ParsingException if something wrong is found wrt the language
     */
    private boolean execute_http(HTTPReqRes message,
                                 boolean isRequest) throws ParsingException {
        String msg_str = "";
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
                msg_str = String.join("\r\n", message.getHeaders(isRequest));
                break;
            default:
                System.err.println("no valid \"in\" specified in check");
                return false;
        }

        if (msg_str.length() == 0) {
            return false;
        }

        // if a regex is present, execute it
        if (!regex.equals("")) {
            return execute_regex(msg_str);
        }

        if (this.isParamCheck) {
            if (in == CheckIn.BODY) {
                applicable = false;
                throw new ParsingException("Invalid check operation, cannot do \"check param\" over body, " +
                        "use \"check_regex instead\"");
            }

            Pattern p = this.in == CheckIn.URL ?
                    Pattern.compile("(?<=[?&]" + this.what + "=)[^\\r\\n&]*") :
                    Pattern.compile("(?<=" + this.what + ":\\s?)[^\\r\\n]*");
            // TODO: this could be done better by using message methods
            Matcher m = p.matcher(msg_str);

            applicable = true;

            String val = "";
            if (m.find()) {
                val = m.group();
                val = val.trim();
            } else {
                //return false; // TODO: check if correct, is not present?
            }

            return do_check(val);
        } else {
            applicable = true;
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
     * @return the result of the execution
     * @throws ParsingException if something wrong is found wrt the language
     */
    private boolean execute_json() throws ParsingException {
        DecodeOperation_API tmp = ((DecodeOperation_API) this.imported_api);

        if (isParamCheck) {
            throw new ParsingException("Cannot execute a 'check param' in a json, please use 'check'");
        }

        String j = "";

        switch (in) {
            case JWT_HEADER: {
                j = tmp.jwt.header;
                break;
            }
            case JWT_PAYLOAD: {
                j = tmp.jwt.payload;
                break;
            }
            case JWT_SIGNATURE: {
                j = tmp.jwt.signature;
                break;
            }
        }

        // if a regex is present, execute it
        if (!regex.equals("")) {
            return execute_regex(j);
        }

        String found = "";
        // https://github.com/json-path/JsonPath
        try {
            Object found_obj = JsonPath.read(j, what);
            found = (String) found_obj;
        } catch (com.jayway.jsonpath.PathNotFoundException e) {
            applicable = true;
            return op == IS_NOT_PRESENT;
        } catch (java.lang.ClassCastException e) {
            throw new ParsingException("Invalid JSON Path in check operation, the value matched is an array, please " +
                    "specify the element to be matched with the correct json PATH, i.e. by using ...[0]");
        }

        applicable = true; // at this point the path has been found so the check is applicable

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
            case IS_IN:
                return value_list.contains(found);
            case IS_NOT_IN:
                return !value_list.contains(found);
        }

        return false;
    }

    /**
     * Executes check operations over the selected value, and returns the result
     *
     * @param val_to_check the value to check
     * @return the result of the check
     */
    public boolean do_check(String val_to_check) {
        try {
            if (this.op == null && val_to_check.length() != 0) {
                // if it passed all the splits without errors, the param is present, but no checks are specified
                // so result is true
                return true;
            }
            switch (this.op) {
                case IS:
                    if (!this.op_val.equals(val_to_check)) {
                        return false;
                    }
                    break;
                case IS_NOT:
                    if (this.op_val.equals(val_to_check)) {
                        return false;
                    }
                    break;
                case CONTAINS:
                    if (!val_to_check.contains(this.op_val)) {
                        return false;
                    }
                    break;
                case NOT_CONTAINS:
                    if (val_to_check.contains(this.op_val)) {
                        return false;
                    }
                    break;
                case IS_PRESENT:
                    return !val_to_check.isEmpty(); // if it gets to this, the searched param is already found
                case IS_NOT_PRESENT:
                    return val_to_check.isEmpty();
                case IS_IN:
                    return value_list.contains(val_to_check); // TODO check
                case IS_NOT_IN:
                    return !value_list.contains(val_to_check);
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
        return true;
    }

    /**
     * Executes the given check (without API). Used to match messages with msg_types usually.
     *
     * @param message   the message to check
     * @param isRequest if the message is a request or a response
     * @return the result of the check (passed or not passed)
     */
    public boolean execute(HTTPReqRes message,
                           boolean isRequest,
                           List<Var> vars) throws ParsingException {

        if (use_variable) {
            // Substitute to the op_val variable (that contains the name), the value of the variable
            op_val = Tools.getVariableByName(op_val, vars).value;
        }
        result = execute_http(message, isRequest);
        return result;
    }

    /**
     * Execute the check by using API
     *
     * @param vars the variables of the actual operation (test)
     */
    public void execute(List<Var> vars) throws ParsingException {
        if (use_variable) {
            // Substitute to the op_val variable (that contains the name), the value of the variable
            op_val = Tools.getVariableByName(op_val, vars).value;
        }

        if (imported_api instanceof Operation_API) {
            // If is inside a standard Operation
            result = execute_http(
                    ((Operation_API) imported_api).message,
                    ((Operation_API) imported_api).is_request
            );
        } else if (imported_api instanceof DecodeOperation_API) {
            // if inside a decode operation
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
    }

    public void setWhat(String what) {
        this.what = what;
    }

    public void setOp(CheckOps op) {
        this.op = op;
    }

    @Override
    public String toString() {
        return "check: " + what + (op == null ? "" : " " + op + ": " + op_val);
    }

    /**
     * enum containing all the possible check operations
     */
    public enum CheckOps {
        IS,
        IS_NOT,
        CONTAINS,
        NOT_CONTAINS,
        IS_PRESENT,
        IS_NOT_PRESENT,
        IS_IN,
        IS_NOT_IN;

        /**
         * Function that given a String, returns the corresponding CheckOps enum's value
         *
         * @param input the input string
         * @return the CheckOps enum value
         * @throws ParsingException if the input string does not correspond to any of the possible check operations
         */
        public static CheckOps fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "is":
                        return IS;
                    case "is not":
                        return IS_NOT;
                    case "contains":
                        return CONTAINS;
                    case "not contains":
                        return NOT_CONTAINS;
                    case "is in":
                        return IS_IN;
                    case "is not in":
                        return IS_NOT_IN;
                    default:
                        throw new ParsingException("invalid check operation");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }

    /**
     * Used in the Check operation, to specify where is the content to check.
     */
    public enum CheckIn {
        // standard message
        HEAD,
        BODY,
        URL,
        // jwt
        JWT_HEADER,
        JWT_PAYLOAD,
        JWT_SIGNATURE;

        public static CheckIn fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "head":
                        return HEAD;
                    case "body":
                        return BODY;
                    case "url":
                        return URL;
                    case "header":
                        return JWT_HEADER;
                    case "payload":
                        return JWT_PAYLOAD;
                    case "signature":
                        return JWT_SIGNATURE;
                    default:
                        throw new ParsingException("invalid in '" + input + "' for check");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }
}
