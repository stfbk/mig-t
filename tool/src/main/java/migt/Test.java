package migt;

import burp.IInterceptedProxyMessage;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Class to store a test
 *
 * @author Matteo Bitussi
 */
public class Test {
    public Utils.ResultType result;
    public String resultSession;
    public List<Session> sessions;
    public String references;
    public String violated_properties;
    public String affected_entity;
    public String mitigations;
    Boolean isActive;
    List<Operation> operations;
    boolean success = false;
    boolean applicable = true;
    boolean error = false;
    String error_srt;
    // Infos
    String name;
    String description;

    /**
     * Instantiate a test
     */
    public Test() {
        this.resultSession = "";
        this.name = "";
        this.description = "";
        this.error_srt = "";
        this.operations = new ArrayList<>();
        this.sessions = new ArrayList<>();

        this.success = false;
        this.isActive = false;

        references = "";
        violated_properties = "";
        mitigations = "";
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
     * This function returns a list of String arrays, containing all the informations of all the matched/unmatched
     * messages during the execution of the operations in the test
     *
     * @return a list of String array to be put on a table with 5 columns
     */
    public List<String[]> getRows() {
        List<String[]> res = new ArrayList<>();

        int count = 0;
        for (Operation op : operations) {
            for (Operation.MatchedMessage msg : op.matchedMessages) {
                String[] tmp = new String[]{
                        String.valueOf(count),
                        String.valueOf(op.getMessageType()),
                        String.valueOf(op.getMessageSection()),
                        op.isRegex ? op.getRegex() : op.getChecks().toString(),
                        msg.index.toString(),
                        msg.isFail ? "failed" : "passed"};
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
     * @throws ParsingException     if the param type is not recognized
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
     * Function used to log the test informations, such as matched messages, all the messages intercepted, and sessions
     *
     * @param log_folder The folder where to log the test
     */
    public void logTest(String log_folder) {
        if (this.name.equals("")) {
            return;
        }
        String timestamp = new SimpleDateFormat("yyyy_MM_dd_HH_mm").format(new java.util.Date());
        String test_log_folder = log_folder + "/" + timestamp + "/" + this.name + "/";
        String matched_folder = test_log_folder + "matched/";
        String all_path = test_log_folder + "all/";
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
            String header = "========================= Info ===========================\n";
            header += "=\t" + "Intercepted from session: " + o.from_session + "\n";
            header += "=\t" + "Message name: " + o.getMessageType() + "\n";
            header += "==========================================================\n";
            String base_path = matched_folder +
                    "/operation_" +
                    op_count +
                    "_" + o.getMessageType();
            for (Operation.MatchedMessage m : o.matchedMessages) {
                if (m.message != null) {
                    if (m.message.getRequest() != null) {
                        File log_message = new File(base_path + "_request.raw");
                        try {
                            FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
                            BufferedWriter bw = new BufferedWriter(fw);
                            bw.write(header);
                            bw.write(new String(m.message.getRequest(), StandardCharsets.UTF_8));
                            bw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        message_count++;
                    }
                    if (m.message.getResponse() != null) {
                        File log_message = new File(base_path + "_response.raw");
                        try {
                            FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
                            BufferedWriter bw = new BufferedWriter(fw);
                            bw.write(header);
                            bw.write(new String(m.message.getResponse(), StandardCharsets.UTF_8));
                            bw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        message_count++;
                    }
                }
            }

            HashSet<Integer> logged_requests = new HashSet<Integer>();
            if (o.log_messages != null) {
                for (IInterceptedProxyMessage m : o.log_messages) {
                    if (!logged_requests.contains(m.getMessageReference())) {
                        byte[] request = m.getMessageInfo().getRequest();
                        if (request != null) {
                            //log request
                            File log_message = new File(
                                    all_path
                                            + m.getMessageReference()
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
                        logged_requests.add(m.getMessageReference());
                    }

                    byte[] response = m.getMessageInfo().getResponse();
                    if (response != null) {
                        //log response
                        File log_message = new File(
                                all_path
                                        + m.getMessageReference()
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
}
