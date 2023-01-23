package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class containing a session Operation
 *
 * @author Matteo Bitussi
 */
public class SessionOperation {
    public String from_session;
    public Utils.SessOperationAction action;
    public String what;
    public String as;
    public String at;
    public String to; // until to which ession action save
    public boolean is_from_included = false;
    public boolean is_to_included = false;
    public Utils.SessOperationTarget target;
    public String mark_name;

    /**
     * Parses a list of session operations from json
     * @param act_operation the session operations as JSON object
     * @return the list of tession operations
     * @throws ParsingException if the parsing goes wrong
     */
    public static List<SessionOperation> parseFromJson(JSONObject act_operation) throws ParsingException {
        List<SessionOperation> lsop = new ArrayList<>();
        if (act_operation.has("session operations")) {
            JSONArray session_ops = act_operation.getJSONArray("session operations");
            for (int l = 0; l < session_ops.length(); l++) {
                JSONObject act_session_op = session_ops.getJSONObject(l);
                SessionOperation sop = new SessionOperation();
                Iterator<String> keys = act_session_op.keys();
                while (keys.hasNext()) {
                    String key = keys.next();

                    switch (key) {
                        case "session":
                            sop.from_session = act_session_op.getString("session");
                            break;
                        case "save":
                            sop.action = Utils.SessOperationAction.SAVE;
                            sop.target = Utils.SessOperationTarget
                                    .getFromString(act_session_op.getString("save"));
                            break;
                        case "as":
                            sop.as = act_session_op.getString("as");
                            break;
                        case "insert":
                            sop.action = Utils.SessOperationAction.INSERT;
                            sop.what = act_session_op.getString("insert");
                            break;
                        case "at":
                            sop.at = act_session_op.getString("at");
                            break;
                        case "mark":
                            sop.action = Utils.SessOperationAction.MARKER;
                            sop.target = Utils.SessOperationTarget
                                    .getFromString(act_session_op.getString("mark"));
                            sop.mark_name = act_session_op.getString("name");
                            break;
                        case "name":
                            //Already processed in mark
                            break;
                        case "remove":
                            sop.action = Utils.SessOperationAction.REMOVE;
                            if (sop.at == null || sop.at.length()==0) {
                                sop.at = act_session_op.getString("remove");
                            }
                            break;

                        case "range":
                            List<Object> res = parseRange(act_session_op.getString("range"));
                            sop.is_from_included = (boolean) res.get(0);
                            sop.is_to_included = (boolean) res.get(1);
                            sop.at = (String) res.get(2);
                            sop.to = (String) res.get(3);
                            break;

                        default:
                            throw new ParsingException("Unexpected value: " + key);
                    }
                }
                lsop.add(sop);
            }
            return lsop;
        }
        return null;
    }

    /**
     * Parse a string containing a range in the form of [number, number] or (number,number], based on the type of
     * parenthesis you can say that the rance is included [ or excluded (
     * @param range The string containing the range to parse
     * @return Position 0, true if from included.
     * Position 1: true if to included.
     * Position 2: from,
     * Position 3: to
     */
    public static List<Object> parseRange(String range) throws ParsingException {
        Pattern p = Pattern.compile("^(\\(|\\[)\\s*([^\\[\\],]*)\\s*,\\s*([^\\[\\],]*)\\s*(\\)|\\])$");
        Matcher m = p.matcher(range);

        List<Object> l = new ArrayList<>();

        List<String> tmp = new ArrayList<>();

        int count = m.groupCount();

        if (count != 4)
            throw new ParsingException("invalid range in session operation: \"" + range + "\"");

        while (m.find()) {
            tmp.add(m.group(1));
            tmp.add(m.group(2));
            tmp.add(m.group(3));
            tmp.add(m.group(4));
        }

        if (tmp.size() != 4)
            throw new ParsingException("invalid range in session operation: \"" + range + "\"");

        l.add(tmp.get(0).equals("["));
        l.add(tmp.get(3).equals("]"));
        l.add(tmp.get(1));
        l.add(tmp.get(2));

        return l;
    }
}
