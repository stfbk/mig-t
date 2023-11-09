package migt;

import com.jayway.jsonpath.JsonPath;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static migt.Check.CheckOps.*;

/**
 * Check Object class. This object is used in Operations to check that a parameter or some text is in as specified.
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
    boolean url_decode = true; // this can be used to disable url decoding

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
                        try {
                            this.op_val = json_check.getString("contains");
                        } catch (JSONException e) {
                            // if not a string try an array
                            JSONArray jsonArr = json_check.getJSONArray("contains");
                            Iterator<Object> it = jsonArr.iterator();

                            while (it.hasNext()) {
                                String act_enc = (String) it.next();
                                value_list.add(act_enc);
                            }
                        }
                        break;
                    case "not contains":
                        this.setOp(CheckOps.NOT_CONTAINS);
                        try {
                            this.op_val = json_check.getString("not contains");
                        } catch (JSONException e) {
                            // if not a string try an array
                            JSONArray jsonArr = json_check.getJSONArray("not contains");
                            Iterator<Object> it = jsonArr.iterator();

                            while (it.hasNext()) {
                                String act_enc = (String) it.next();
                                value_list.add(act_enc);
                            }
                        }
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
                    case "is subset of":
                        this.op = IS_SUBSET_OF;
                        JSONArray jsonArr3 = json_check.getJSONArray("is subset of");
                        Iterator<Object> it3 = jsonArr3.iterator();

                        while (it3.hasNext()) {
                            String act_enc = (String) it3.next();
                            value_list.add(act_enc);
                        }
                        break;
                    case "matches regex":
                        this.op = MATCHES_REGEX;
                        this.op_val = json_check.getString("matches regex");
                        break;
                    case "not matches regex":
                        this.op = NOT_MATCHES_REGEX;
                        this.op_val = json_check.getString("not matches regex");
                        break;
                    case "url decode":
                        url_decode = json_check.getBoolean("url decode");
                        break;
                }
            } catch (JSONException e) {
                throw new ParsingException("error in parsing check: " + e);
            } catch (ClassCastException e) {
                throw new ParsingException("Only allowed values in arrays are Strings, if you are using integers or " +
                        "floats, please convert them as strings");
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
    private boolean execute_regex(String input) throws ParsingException {
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
            applicable = true;
            return this.op != null && op == IS_NOT_PRESENT;
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
                    Pattern.compile("(?<=[?&]" + Pattern.quote(this.what) + "=)[^\\r\\n&]*") :
                    Pattern.compile("(?<=" + Pattern.quote(this.what) + ":\\s?)[^\\r\\n]*");
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
        List<String> found_array = null;
        boolean value_is_array = false;
        // https://github.com/json-path/JsonPath
        try {
            Object found_obj = JsonPath.read(j, what);

            if (op == IS_PRESENT | op == IS_NOT_PRESENT) {
                // whatever is the type of the value, if it is found return the result
                applicable = true;
                return op == IS_PRESENT;
            }

            if (found_obj instanceof net.minidev.json.JSONArray) {
                // the value is a list, allowed ops are: contains/not-contains
                if (!(op == CONTAINS | op == NOT_CONTAINS | op == IS_SUBSET_OF)) {
                    throw new ParsingException("Check error, used " + op.toString() + " over a matched list");
                }

                Iterator<Object> i = ((net.minidev.json.JSONArray) found_obj).iterator();

                List<String> new_array = new ArrayList<>();
                while (i.hasNext()) {
                    try {
                        String elem = String.valueOf(i.next());
                        new_array.add(elem);
                    } catch (java.lang.ClassCastException e) {
                        throw new ParsingException("Cannot convert element in jwt matched array to string");
                    }
                }
                found_array = new_array;
                value_is_array = true;

            } else if (found_obj instanceof java.lang.String) {
                // the value is a string, can do all ops
                found = (String) found_obj;

            } else if (found_obj instanceof java.lang.Double |
                    found_obj instanceof java.lang.Integer) {
                // the value is an double or integer, convert to string
                found = String.valueOf(found_obj);
            }

        } catch (com.jayway.jsonpath.PathNotFoundException e) {
            applicable = true;
            return op == IS_NOT_PRESENT;
        } catch (java.lang.ClassCastException e) {
            throw new ParsingException("Error in check, json matched value cast exception: " + e);
        }

        applicable = true; // at this point the path has been found so the check is applicable

        switch (op) {
            case IS:
                return op_val.equals(found);
            case IS_NOT:
                return !op_val.equals(found);
            case CONTAINS:
                if (!value_is_array)
                    return found.contains(op_val);
                else {
                    // the matched value is an array
                    if (!value_list.isEmpty()) {
                        // check against a value array
                        for (String elem : value_list) {
                            if (!found_array.contains(elem)) {
                                return false;
                            }
                        }
                        return true;
                    } else {
                        // check against single string value
                        return found_array.contains(op_val);
                    }
                }
            case NOT_CONTAINS:
                if (!value_is_array)
                    return !found.contains(op_val);
                else {
                    //the matched value is an array
                    if (!value_list.isEmpty()) {
                        // check against a value array
                        for (String elem : value_list) {
                            if (found_array.contains(elem)) {
                                return false;
                            }
                        }
                        return true;
                    } else {
                        // check against single string value
                        return found_array.contains(op_val);
                    }
                }
            case IS_PRESENT:
                return !found.isEmpty();
            case IS_NOT_PRESENT:
                return found.isEmpty();
            case IS_IN:
                return value_list.contains(found);
            case IS_NOT_IN:
                return !value_list.contains(found);
            case IS_SUBSET_OF:
                if (!value_is_array)
                    throw new ParsingException("Matched single element in jwt, but should be an array when using IS SUBSET OF");

                return value_list.containsAll(found_array);
            case MATCHES_REGEX: {
                if (value_is_array) throw new ParsingException("Check error: cannot execute a regex over a list");
                Pattern p = Pattern.compile(op_val);
                Matcher m = p.matcher(found);
                return m.find();
            }
            case NOT_MATCHES_REGEX: {
                if (value_is_array) throw new ParsingException("Check error: cannot execute a regex over a list");
                Pattern p = Pattern.compile(op_val);
                Matcher m = p.matcher(found);
                return !m.find();
            }
        }

        return false;
    }

    /**
     * Executes check operations over the selected value, and returns the result
     *
     * @param val_to_check the value to check
     * @return the result of the check
     */
    public boolean do_check(String val_to_check) throws ParsingException {
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
                case MATCHES_REGEX: {
                    Pattern p = Pattern.compile(op_val);
                    Matcher m = p.matcher(val_to_check);
                    return m.find();
                }
                case NOT_MATCHES_REGEX: {
                    Pattern p = Pattern.compile(op_val);
                    Matcher m = p.matcher(val_to_check);
                    return !m.find();
                }
                default:
                    throw new ParsingException("Unsupported operand for Check in a message: " + op);
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

        // URL-decode matched content
        // when a string contains a "+" character then, it is replaced with a space.
        if (url_decode) {
            /*
            Pattern p = Pattern.compile("%[0-9a-fA-F]{2}");
            Matcher m = p.matcher(op_val);
            if (m.find()) {
                // if the content contains url-encoded characters then, url-decode the content
                op_val = URLDecoder.decode(op_val, StandardCharsets.UTF_8);
            }
            */
            if (op_val.contains("+")) {
                System.err.println("Warning! During a check on the value\"" + op_val + "\" a '+' symbol has been" +
                        "converted to a space, as it has been interpreted as url-encoded character. If you want to avoid" +
                        "this behaviour use 'url decode' tag set to false inside the check to disable url-decoding ");
            }
            op_val = URLDecoder.decode(op_val, StandardCharsets.UTF_8);
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
        IS_NOT_IN,
        IS_SUBSET_OF,
        MATCHES_REGEX,
        NOT_MATCHES_REGEX;

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
                    case "is subset of":
                        return IS_SUBSET_OF;
                    case "matches regex":
                        return MATCHES_REGEX;
                    case "not matches regex":
                        return NOT_MATCHES_REGEX;
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
