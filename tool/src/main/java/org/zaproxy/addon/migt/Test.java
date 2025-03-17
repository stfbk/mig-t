package org.zaproxy.addon.migt;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import org.parosproxy.paros.network.HttpMessage;

/** Class to store a test */
public class Test {
    public ResultType result;
    public String resultSession;
    public List<Session> sessions;
    public String references;
    public String violated_properties;
    public String affected_entity;
    public String mitigations;
    public List<Var> vars;
    public String error_str;
    public Boolean error;
    Boolean isActive;
    List<Operation> operations;
    boolean success = false;
    boolean applicable = true;
    // Infos
    String name;
    String description;
    List<String> mandatory_keys = new ArrayList<>();

    private byte[] concat(byte[] Fheader, byte[] Fbody) {
        byte[] result = new byte[Fheader.length + Fbody.length];
        System.arraycopy(Fheader, 0, result, 0, Fheader.length);
        System.arraycopy(Fbody, 0, result, Fheader.length, Fbody.length);

        return result;
    }

    /** Empty constructor for tests */
    public Test() {
        init();
    }

    /** Instantiate a test */
    public Test(JSONObject test_json, List<MessageType> messageTypes) throws Exception {
        init();

        description = test_json.getString("description");
        name = test_json.getString("name");
        setType(test_json.getString("type"));

        Iterator<String> keys = test_json.keys();

        for (String k : mandatory_keys) {
            if (!test_json.keySet().contains(k)) {
                throw new ParsingException("Test is missing required \"" + k + "\" key");
            }
        }

        while (keys.hasNext()) {
            String key = keys.next();

            switch (key) {
                case "name":
                case "type":
                case "description":
                case "result":
                case "operations":
                case "sessions":
                    break;
                case "references":
                    references = test_json.getString("references");
                    break;
                case "violated_properties":
                    violated_properties = test_json.getString("violated_properties");
                    break;
                case "mitigations":
                    mitigations = test_json.getString("mitigations");
                    break;
                case "affected_entity":
                    affected_entity = test_json.getString("affected_entity");
                    break;
                default:
                    throw new ParsingException("Invalid key \"" + key + "\" in test");
            }
        }

        // set result
        if (isActive) {
            if (test_json.has("result")) {
                String tmp = test_json.getString("result");
                if (tmp.contains("assert_only")) {
                    result = ResultType.fromString(tmp);
                } else {
                    tmp = tmp.trim();
                    String[] splitted = tmp.split("flow");

                    if (splitted.length > 1) {
                        resultSession = splitted[1].trim();
                    }
                    result = ResultType.fromString(splitted[0].trim());
                }
            }
        }

        if (test_json.has("sessions")) {
            JSONArray arrSess = test_json.getJSONArray("sessions");
            Iterator<Object> it = arrSess.iterator();

            while (it.hasNext()) {
                String act_sess_name = (String) it.next();
                sessions.add(new Session(act_sess_name));
            }
        } else {
            throw new ParsingException("session tag is missing");
        }

        // Array of Operations
        JSONArray arrOps = test_json.getJSONArray("operations");

        // Reads all the operations
        for (int j = 0; j < arrOps.length(); j++) {
            JSONObject act_operation = arrOps.getJSONObject(j);

            Operation op = new Operation(act_operation, isActive, messageTypes);
            operations.add(op);
        }
    }

    public void init() {
        vars = new ArrayList<>();
        this.resultSession = "";
        this.name = "";
        this.description = "";
        this.operations = new ArrayList<>();
        this.sessions = new ArrayList<>();
        this.error_str = "";
        this.error = false;

        this.success = false;
        this.isActive = false;

        references = "";
        violated_properties = "";
        mitigations = "";

        // mandatory_keys.add("result") // for manuals is not required
        mandatory_keys.add("name");
        mandatory_keys.add("type");
        mandatory_keys.add("sessions");
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (name != null) {
            this.name = name;
        } else {
            throw new NullPointerException();
        }
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * This function returns a list of String arrays, containing all the informations of all the
     * matched/unmatched messages during the execution of the operations in the test
     *
     * @return a list of String array to be put on a table with 5 columns
     */
    public List<String[]> getRows() {
        List<String[]> res = new ArrayList<>();

        int count = 0;
        for (Operation op : operations) {
            for (HTTPReqRes msg : op.matchedMessages) {
                String[] tmp =
                        new String[] {
                            String.valueOf(count),
                            String.valueOf(op.getMessageType()),
                            "",
                            op.getChecks().toString(),
                            msg.index.toString(),
                            "-"
                        }; // TODO: somehow put if the message made the test fail
                res.add(tmp);
            }
            count++;
        }
        return res;
    }

    /**
     * Set the type of the test
     *
     * @param type a String that can be either "passive" or "active"
     * @throws ParsingException if the param type is not recognized
     * @throws NullPointerException if type is null
     */
    public void setType(String type) throws ParsingException, NullPointerException {
        if (type != null) {
            if (type.equals("passive")) {
                this.isActive = false;
            } else if (type.equals("active")) {
                this.isActive = true;
            } else {
                throw new ParsingException("incorrect type definition");
            }
        } else {
            throw new NullPointerException("type is null");
        }
    }

    /**
     * Get a session by its name
     *
     * @param session_name the session's name
     * @return the session
     */
    public Session getSession(String session_name) throws ParsingException {
        for (Session s : sessions) {
            if (s.name.equals(session_name)) {
                return s;
            }
        }
        throw new ParsingException("Undefined session");
    }

    /**
     * Function used to logs informations about the test, such as matched messages, all the messages
     * intercepted, and sessions
     *
     * @param log_folder The folder containing all the mig-t logs
     */
    public void logTest(String log_folder) {
        if (this.name.isEmpty()) {
            return;
        }
        String timestamp = new SimpleDateFormat("yyyy_MM_dd_HH_mm").format(new java.util.Date());
        String test_log_folder = log_folder + "/" + timestamp + "/" + this.name + "/";
        String matched_folder = test_log_folder + "matched/";
        String all_path = test_log_folder + "all/";
        String test_log_path = test_log_folder + "test.log";
        File directory = new File(test_log_folder);
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                System.err.println("cannot create log directory at " + test_log_folder);
            }
        }
        directory = new File(matched_folder);
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                System.err.println("cannot create log directory at " + matched_folder);
            }
        }
        directory = new File(all_path);
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                System.err.println("cannot create log directory at " + all_path);
            }
        }

        String test_log_content = "Name: " + this.name + "\n";

        test_log_content += "Variables: \n";

        for (Var v : vars) {
            try {
                test_log_content += v.name = v.value + "\n";
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        File test_log = new File(test_log_path);
        try {
            FileWriter fw = new FileWriter(test_log.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(test_log_content);
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        for (Session s : this.sessions) {
            if (s.name.equals("")) {
                continue;
            }
            File log_sessions = new File(test_log_folder + "/" + s.name + ".log");
            try {
                FileWriter fw = new FileWriter(log_sessions.getAbsoluteFile());
                BufferedWriter bw = new BufferedWriter(fw);
                bw.write(s.track.toString());
                bw.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        Integer op_count = 0;
        for (Operation o : this.operations) {
            Integer message_count = 0;
            String header = "===================== Operation Info =========================\n";
            header += "Checks: ====================================\n";
            for (Check c : o.getChecks()) {
                header += c.toStringExtended();
            }
            header += "Decode Operations: =========================\n";
            for (DecodeOperation d : o.getDecodeOperations()) {
                header += d.toStringExtended();
            }

            header += "\n\n";
            header += "===================== Message info =========================\n";
            header += "=\t" + "Intercepted from session: " + o.from_session + "\n";
            header += "=\t" + "Message name: " + o.getMessageType() + "\n";
            header += "==========================================================\n";
            String base_path = matched_folder + "/operation_" + op_count + "_" + o.getMessageType();
            for (HTTPReqRes m : o.matchedMessages) {
                if (m != null) {
                    if (m.getRequest() != null) {
                        File log_message = new File(base_path + "_request.raw");
                        try {
                            FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
                            BufferedWriter bw = new BufferedWriter(fw);
                            bw.write(header);
                            bw.write(new String(m.getRequest(), StandardCharsets.UTF_8));
                            bw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        message_count++;
                    }
                    if (m.getResponse() != null) {
                        File log_message = new File(base_path + "_response.raw");
                        try {
                            FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
                            BufferedWriter bw = new BufferedWriter(fw);
                            bw.write(header);
                            bw.write(new String(m.getResponse(), StandardCharsets.UTF_8));
                            bw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        message_count++;
                    }
                }
            }

            HashSet<Integer> logged_requests = new HashSet<Integer>();

            // TODO HistoryID should work but need to check

            // Save all messages seen by this operation
            if (o.log_messages != null) {
                for (HttpMessage m : o.log_messages) {
                    if (!logged_requests.contains(m.getHistoryRef().getHistoryId())) {
                        byte[] request =
                                concat(
                                        m.getRequestHeader().toString().getBytes(),
                                        m.getResponseBody().getBytes());
                        if (request != null) {
                            // log request
                            File log_message =
                                    new File(
                                            all_path
                                                    + m.getHistoryRef().getHistoryId()
                                                    + "_request.raw");
                            try {
                                FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
                                BufferedWriter bw = new BufferedWriter(fw);
                                bw.write(new String(request, StandardCharsets.UTF_8));
                                bw.close();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                        logged_requests.add(m.getHistoryRef().getHistoryId());
                    }

                    byte[] response =
                            concat(
                                    m.getResponseHeader().toString().getBytes(),
                                    m.getResponseBody().getBytes());
                    if (response != null) {
                        // log response
                        File log_message =
                                new File(
                                        all_path
                                                + m.getHistoryRef().getHistoryId()
                                                + "_response.raw");
                        try {
                            FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
                            BufferedWriter bw = new BufferedWriter(fw);
                            bw.write(new String(response, StandardCharsets.UTF_8));
                            bw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }

            // Save edited message
            if (o.processed_message != null) {
                File log_message = new File(base_path + "_edited.raw");
                try {
                    FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
                    BufferedWriter bw = new BufferedWriter(fw);
                    bw.write(header);
                    bw.write(new String(o.processed_message, StandardCharsets.UTF_8));
                    bw.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }

            op_count++;
        }
    }

    /**
     * Function that execute the given passive test.
     *
     * @param messageList a list of <code>HTTPReqRes</code> messages
     * @param msg_types the message types used by the test
     * @return true if a test is passed, false otherwise
     */

    //jump here -- remove this comment

    public boolean execute(List<HTTPReqRes> messageList, List<MessageType> msg_types)
            throws ParsingException {

        System.out.println("Entrato in execute di Test");


        int i, j;
        boolean res = true;

        for (i = 0; i < messageList.size(); i++) {
            j = 0;
            while (j < operations.size() && res) {
                Operation currentOP = operations.get(j);
                MessageType msg_type =
                        MessageType.getFromList(msg_types, currentOP.getMessageType());



                if (currentOP.api == null) {
                    currentOP.api = new Operation_API(vars);
                } else {
                    currentOP.api.vars = vars;
                }


                System.err.println("Risultato per IF --------------------> " + messageList.get(i).matches_msg_type(msg_type, msg_type.msg_to_process_is_request));

                for (Check c : msg_type.checks){
                    System.err.println(c.regex);
                }

                if (messageList.get(i).matches_msg_type(msg_type, msg_type.msg_to_process_is_request)) {

                    System.out.println("Punto di richiamo di execute");

                    currentOP.setAPI(
                            new Operation_API(
                                    messageList.get(i), msg_type.msg_to_process_is_request));
                    currentOP.execute();
                    res = currentOP.getResult();
                }

                vars = currentOP.api.vars;
                j++;
            }
        }

        for (Operation op : operations) {
            if (!op.applicable) {
                res = false;
                applicable = false;
                break;
            }
        }

        System.out.println("About to return --> " + res);

        return res;
    }

    /** The result type of (also the oracle) of an Active test */
    public enum ResultType {
        CORRECT_FLOW,
        INCORRECT_FLOW,
        ASSERT_ONLY;

        /**
         * From a string get the corresponding enum value
         *
         * @param input the string
         * @return the enum value
         * @throws ParsingException if the input is malformed
         */
        public static ResultType fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "correct":
                        return CORRECT_FLOW;
                    case "incorrect":
                        return INCORRECT_FLOW;
                    case "assert_only":
                        return ASSERT_ONLY;
                    default:
                        throw new ParsingException("invalid result");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }
}
