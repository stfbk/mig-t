package burp;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static burp.Utils.executeDecodeOps;
import static burp.Utils.getVariableByName;

/**
 * Main class executed by Burp
 *
 * @author Matteo Bitussi
 */
public class BurpExtender implements IBurpExtender, ITab, IProxyListener {

    public static IExtensionHelpers helpers;
    public static PrintStream printStream;
    public static PrintStream errorStream;
    public IBurpExtenderCallbacks callbacks;
    private GUI mainPane; // The GUI

    /**
     * Main function creating the extension
     *
     * @param callbacks The callbacks received by Burp
     */
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        try {
            System.setOut(new PrintStream("output_log.txt")); // Changes the default outstream with this file
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            System.setErr(new PrintStream("error_log.txt"));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        System.out.println("Initializing extension");

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();

        callbacks.setExtensionName("MIG Testing tool");

        //The UI is created
        SwingUtilities.invokeLater(() -> {
            // setup output stream
            OutputStream stdOut = callbacks.getStdout();
            OutputStream stdErr = callbacks.getStderr();
            printStream = new PrintStream(stdOut);
            errorStream = new PrintStream(stdErr);

            mainPane = new GUI();
            mainPane.helpers = callbacks.getHelpers();
            mainPane.callbacks = callbacks;
            mainPane.messageViewer = callbacks.createMessageEditor(mainPane.controller, false);
            mainPane.splitPane.setRightComponent(mainPane.messageViewer.getComponent());

            // add the custom tab to Burp's UI
            callbacks.addSuiteTab(BurpExtender.this);

            // register ourselves as an HTTP listener
            callbacks.registerProxyListener(BurpExtender.this);
            //callbacks.registerHttpListener(BurpExtender.this);
        });
    }

    @Override
    public String getTabCaption() {
        return "MIG-T";
    }

    @Override
    public Component getUiComponent() {
        return mainPane;
    }


    /**
     * Proxy's listener function which is called wheter a new message arrives. Note that if the received message is a
     * request, you cannot access the response
     *
     * @param messageIsRequest Indicates whether the HTTP message is a request
     *                         or a response.
     * @param message          An
     *                         <code>IInterceptedProxyMessage</code> object that extensions can use to
     *                         query and update details of the message, and control whether the message
     *                         should be intercepted and displayed to the user for manual review or
     */
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        String port = message.getListenerInterface().split(":")[1];
        IHttpRequestResponse messageInfo = message.getMessageInfo();

        if (mainPane.ACTIVE_ENABLED) {
            if (!port.equals(mainPane.act_active_op.session_port)) {
                return;
            }

            log_message(messageIsRequest, message);

            boolean matchMessage = false;
            try {
                switch (mainPane.act_active_op.getMessageType()) {
                    case "request":
                        if (messageIsRequest) {
                            matchMessage = true;
                        }
                        break;
                    case "response":
                        if (!messageIsRequest) {
                            matchMessage = true;
                        }
                        break;

                    default:
                        MessageType msg_type = MessageType.getFromList(mainPane.messageTypes,
                                mainPane.act_active_op.getMessageType());
                        /* If the response message name is searched, the getByResponse will be true.
                         * so i have to search for the request, and then evaluate the response*/
                        if (msg_type.getByResponse) {
                            if (!messageIsRequest) {
                                if (msg_type.isRegex) {
                                    matchMessage = Tools.findInMessage(msg_type.messageSection,
                                            msg_type.regex,
                                            new HTTPReqRes(messageInfo, helpers, true),
                                            helpers, true);
                                } else {
                                    matchMessage = Tools.executeChecks(msg_type.checks,
                                            new HTTPReqRes(messageInfo, helpers, true),
                                            helpers, true);
                                }
                            }
                        } else if (msg_type.getByRequest) {
                            if (!messageIsRequest) {
                                if (msg_type.isRegex) {
                                    matchMessage = Tools.findInMessage(msg_type.messageSection,
                                            msg_type.regex,
                                            new HTTPReqRes(messageInfo, helpers, false),
                                            helpers, false);
                                } else {
                                    matchMessage = Tools.executeChecks(msg_type.checks,
                                            new HTTPReqRes(messageInfo, helpers, false),
                                            helpers, false);
                                }
                            }
                        } else {
                            if (messageIsRequest == msg_type.isRequest) {
                                if (msg_type.isRegex) {
                                    matchMessage = Tools.findInMessage(msg_type.messageSection,
                                            msg_type.regex,
                                            new HTTPReqRes(messageInfo, helpers, msg_type.isRequest),
                                            helpers, msg_type.isRequest);
                                } else {
                                    matchMessage = Tools.executeChecks(msg_type.checks,
                                            new HTTPReqRes(messageInfo, helpers, msg_type.isRequest),
                                            helpers,
                                            msg_type.isRequest);
                                }
                            }
                        }
                        if (matchMessage) {
                            boolean isRequest = false;
                            if (msg_type.getByRequest) {
                                isRequest = false;
                            } else if (msg_type.getByResponse) {
                                isRequest = true;
                            } else {
                                isRequest = msg_type.isRequest;
                            }

                            Operation.MatchedMessage m = new Operation.MatchedMessage(
                                    new HTTPReqRes(messageInfo, helpers, isRequest),
                                    HTTPReqRes.instances,
                                    isRequest,
                                    !isRequest,
                                    false);
                            mainPane.act_active_op.matchedMessages.add(m);
                        }
                }
            } catch (Exception e) {
                e.printStackTrace();
                mainPane.act_active_op.applicable = false;
            }

            switch (mainPane.act_active_op.getAction()) {
                // If the operation's action is an intercept
                case INTERCEPT:
                    try {
                        switch (mainPane.act_active_op.getMessageType()) {
                            case "request":
                                if (matchMessage) {
                                    processMatchedMsg(new MessageType("request", true), messageInfo);
                                }
                                break;
                            case "response":
                                if (matchMessage) {
                                    processMatchedMsg(new MessageType("request", false), messageInfo);
                                }
                                break;

                            default:
                                MessageType msg_type = MessageType.getFromList(mainPane.messageTypes,
                                        mainPane.act_active_op.getMessageType());
                                /* If the response message name is searched, the getByResponse will be true.
                                 * so i have to search for the request, and then evaluate the response*/
                                if (msg_type.getByResponse) {
                                    if (!messageIsRequest) {
                                        if (matchMessage) {
                                            processMatchedMsg(msg_type, messageInfo);
                                        }
                                    }
                                } else if (msg_type.getByRequest) {
                                    if (!messageIsRequest) {
                                        if (matchMessage) {
                                            processMatchedMsg(msg_type, messageInfo);
                                        }
                                    }
                                } else {
                                    if (messageIsRequest == msg_type.isRequest) {
                                        if (matchMessage) {
                                            processMatchedMsg(msg_type, messageInfo);
                                            if (mainPane.act_active_op.then != null &
                                                    mainPane.act_active_op.then == Utils.Then.DROP) {
                                                message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                                            }
                                        }
                                    }
                                }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        mainPane.act_active_op.applicable = false;
                    }
                    break;

                // if the operation action is a validate
                case VALIDATE:
                    if (matchMessage & (
                            mainPane.act_active_op.to_match == -1 ||
                                    mainPane.act_active_op.to_match > mainPane.act_active_op.act_matched)) {
                        if (!messageIsRequest) {
                            messageInfo.setHighlight("green");
                            List<Boolean> results = null;
                            try {
                                results = Tools.executePassiveOperation(mainPane.act_active_op,
                                        new HTTPReqRes(messageInfo, helpers, messageIsRequest),
                                        0,
                                        helpers,
                                        mainPane.messageTypes);
                            } catch (ParsingException e) {
                                e.printStackTrace();
                                mainPane.act_active_op.applicable = false;
                                resume();
                            }

                            mainPane.act_active_op.applicable = results.get(3);
                            if (mainPane.act_active_op.applicable) {
                                mainPane.act_active_op.result = results.get(0);
                                if (!mainPane.act_active_op.result) resume();
                                mainPane.act_active_op.act_matched++;
                            }
                            resume();
                        }
                    }
                    break;
            }

        }
        if (mainPane.recording) {
            if (!messageIsRequest) { // do not remove
                synchronized (mainPane.interceptedMessages) {
                    IHttpRequestResponsePersisted actual = callbacks.saveBuffersToTempFiles(messageInfo);
                    mainPane.interceptedMessages.add(
                            new HTTPReqRes(actual, helpers)
                    );
                    if (mainPane.defaultSession != null) {
                        mainPane.defaultSession.addMessage(actual, helpers, mainPane.FILTERING);
                    }
                }
            }
        }
    }

    private void processMatchedMsg(MessageType msg_type,
                                   IHttpRequestResponse messageInfo) {
        messageInfo.setHighlight("red");
        HTTPReqRes message = new HTTPReqRes(messageInfo, helpers, msg_type.isRequest);
        mainPane.act_active_op = executeOperation(mainPane.act_active_op,
                message,
                msg_type.isRequest);
        if (mainPane.act_active_op.processed_message != null) {
            if (msg_type.isRequest) {
                //TODO use replace Burp Message ?
                messageInfo.setRequest(mainPane.act_active_op.processed_message);
            } else {
                messageInfo.setResponse(mainPane.act_active_op.processed_message);
            }
        }
        resume();
    }

    /**
     * Executes an operation to a message, in an active test and then returns the updated Operation object, which will
     * contains the infos about the execution
     *
     * @param op          the operation to be executed
     * @param messageInfo the message info
     * @param isRequest   true if the message is a request
     * @return the updated operation, with its result
     */
    private Operation executeOperation(Operation op, HTTPReqRes messageInfo, boolean isRequest) {
        if (!op.preconditions.isEmpty()) {
            try {
                op.applicable = Tools.executeChecks(op.preconditions,
                        messageInfo,
                        helpers,
                        isRequest);
                if (!op.applicable) return op;
            } catch (ParsingException e) {
                op.applicable = false;
                e.printStackTrace();
                return op;
            }
        }

        // Replace the message with the saved one if asked
        if (isRequest) {
            if (!op.replace_request_name.equals("")) {
                try {
                    op.applicable = true;
                    op.processed_message = getVariableByName(op.replace_request_name, mainPane).message;
                    op.processed_message_service = getVariableByName(op.replace_request_name, mainPane).service_info;
                    //return op;
                } catch (ParsingException e) {
                    e.printStackTrace();
                    op.applicable = false;
                    return op;
                }
            }
        } else {
            if (!op.replace_response_name.equals("")) {
                try {
                    op.applicable = true;
                    op.processed_message = getVariableByName(op.replace_response_name, mainPane).message;
                    op.processed_message_service = getVariableByName(op.replace_response_name, mainPane).service_info;
                    //return op;
                } catch (ParsingException e) {
                    e.printStackTrace();
                    op.applicable = false;
                    return op;
                }
            }
        }

        // execute the message operations and the decode ops
        try {
            op.applicable = true;
            op = executeMessageOps(op, messageInfo, isRequest);
            if (!op.applicable | !op.result)
                return op;
            op = executeDecodeOps(op, messageInfo, isRequest, helpers, mainPane);
            if (!op.applicable | !op.result)
                return op;

        } catch (ParsingException | PatternSyntaxException e) {
            op.applicable = false;
            e.printStackTrace();
            return op;
        }

        if (!op.save_name.equals("")) {
            Var v = new Var();
            v.name = op.save_name;
            v.isMessage = true;
            v.message = isRequest ? messageInfo.getRequest() : messageInfo.getResponse();
            v.service_info = messageInfo.getHttpService(helpers);
            synchronized (mainPane.lock) {
                mainPane.act_test_vars.add(v);
            }
        }

        return op;
    }

    /**
     * Given an operation, and a message, execute the Message operations contained in the operation
     *
     * @param op          the operation containing the message operations
     * @param messageInfo the message
     * @param isRequest   true if the message is a request
     * @return the updated Operation with the result
     * @throws ParsingException if parsing of names is not successfull
     */
    public Operation executeMessageOps(Operation op,
                                       HTTPReqRes messageInfo,
                                       boolean isRequest) throws ParsingException {
        for (MessageOperation mop : op.getMessageOerations()) {
            List<String> splitted;
            Pattern pattern;
            Matcher matcher;
            byte[] new_message;

            try {
                if (mop.type == Utils.MessageOpType.GENERATE_POC) {
                    if (!isRequest) {
                        throw new ParsingException("Invalid POC generation, message should be a request");
                    }

                    if (!mop.template.equals("csrf")) {
                        continue; // other templates not supported yet
                    }

                    String poc = Utils.generate_CSRF_POC(messageInfo, helpers);

                    try {
                        File myObj = new File(mop.output_path);
                        myObj.createNewFile();
                    } catch (IOException e) {
                        throw new ParsingException("Invalid POC generation output path: "
                                + mop.output_path + " " + e.getMessage());
                    }
                    try {
                        FileWriter myWriter = new FileWriter(mop.output_path);
                        myWriter.write(poc);
                        myWriter.close();
                    } catch (IOException e) {
                        throw new ParsingException("Something went wrong while writing output file for POC generator: "
                                + mop.output_path + " " + e.getMessage());
                    }
                } else {
                    if (mop.action != null) {
                        switch (mop.action) {
                            case REMOVE_PARAMETER:
                                switch (mop.from) {
                                    case URL:
                                        // Works
                                        if (!isRequest) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String url_header = messageInfo.getUrlHeader();
                                        pattern = Pattern.compile("&?" + mop.what + "=[^& ]*((?=&)|(?= ))");
                                        matcher = pattern.matcher(url_header);
                                        String new_url = matcher.replaceFirst("");
                                        messageInfo.setUrlHeader(new_url);
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;

                                    case HEAD:
                                        messageInfo.removeHeadParameter(isRequest, mop.what);
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;

                                    case BODY:
                                        String body = new String(messageInfo.getBody(isRequest));
                                        pattern = Pattern.compile(mop.what);
                                        matcher = pattern.matcher(body);
                                        messageInfo.setBody(isRequest, matcher.replaceAll(""));
                                        //Automatically update content-lenght
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                }
                                break;

                            case ADD:
                                if (getAdding(mop) == null | getAdding(mop).equals("")) {
                                    // TODO: should raise exception or set operation not applicable?
                                    break;
                                }
                                switch (mop.from) {
                                    case HEAD: {
                                        messageInfo.addHeadParameter(isRequest, mop.what, getAdding(mop));
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                    }
                                    case BODY: {
                                        String tmp = new String(messageInfo.getBody(isRequest));
                                        tmp = tmp + getAdding(mop);
                                        messageInfo.setBody(isRequest, tmp);
                                        //Automatically update content-lenght
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                    }
                                    case URL:
                                        if (!isRequest) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String header_0 = messageInfo.getUrlHeader();

                                        pattern = Pattern.compile("&?" + mop.what + "=[^& ]*((?=&)|(?= ))");
                                        matcher = pattern.matcher(header_0);

                                        String newHeader_0 = "";
                                        boolean found = false;
                                        while (matcher.find() & !found) {
                                            String before = header_0.substring(0, matcher.end());
                                            String after = header_0.substring(matcher.end());
                                            newHeader_0 = before + getAdding(mop) + after;
                                            found = true;
                                        }
                                        messageInfo.setUrlHeader(newHeader_0);
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                }
                                break;

                            case EDIT:
                                op.processed_message = Utils.editMessageParam(
                                        helpers,
                                        mop.what,
                                        mop.from,
                                        messageInfo,
                                        isRequest,
                                        getAdding(mop),
                                        true);
                                break;

                            case EDIT_REGEX:
                                op.processed_message = Utils.editMessage(
                                        helpers,
                                        mop.what,
                                        mop,
                                        messageInfo,
                                        isRequest,
                                        getAdding(mop));
                                break;

                            case REMOVE_MATCH_WORD:
                                switch (mop.from) {
                                    case HEAD: {
                                        List<String> headers = messageInfo.getHeaders(isRequest);
                                        pattern = Pattern.compile(mop.what);
                                        List<String> new_headers = new ArrayList<>();

                                        for (String header : headers) {
                                            matcher = pattern.matcher(header);
                                            new_headers.add(matcher.replaceAll(""));
                                        }

                                        messageInfo.setHeaders(isRequest, new_headers);
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                    }
                                    case BODY: {
                                        pattern = Pattern.compile(mop.what);
                                        matcher = pattern.matcher(new String(messageInfo.getBody(isRequest)));
                                        messageInfo.setBody(isRequest, matcher.replaceAll(""));

                                        //Automatically update content-lenght
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                    }
                                    case URL:
                                        // Works
                                        if (!isRequest) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String header_0 = messageInfo.getUrlHeader();

                                        pattern = Pattern.compile(mop.what);
                                        matcher = pattern.matcher(header_0);
                                        String newHeader_0 = matcher.replaceFirst("");

                                        messageInfo.setUrlHeader(newHeader_0);
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                }
                                break;

                            case SAVE:
                            case SAVE_MATCH:
                                switch (mop.from) {
                                    case HEAD: {
                                        String value = "";
                                        if (mop.action == Utils.MessageOperationActions.SAVE) {
                                            value = messageInfo.getHeadParam(isRequest, mop.what).trim();
                                        } else {
                                            List<String> headers = messageInfo.getHeaders(isRequest);
                                            pattern = Pattern.compile(mop.what);
                                            for (String h : headers) {
                                                matcher = pattern.matcher(h);
                                                value = "";
                                                while (matcher.find()) {
                                                    value = matcher.group();
                                                    break;
                                                }
                                            }
                                        }

                                        Var v = new Var();
                                        v.name = mop.save_as;
                                        v.isMessage = false;
                                        v.value = value;
                                        synchronized (mainPane.lock) {
                                            mainPane.act_test_vars.add(v);
                                        }
                                        break;
                                    }
                                    case BODY: {
                                        String tmp = new String(messageInfo.getBody(isRequest), StandardCharsets.UTF_8);
                                        pattern = Pattern.compile(mop.what);
                                        matcher = pattern.matcher(tmp);
                                        Var v = new Var();

                                        while (matcher.find()) {
                                            v.name = mop.save_as;
                                            v.isMessage = false;
                                            v.value = matcher.group();
                                            break;
                                        }
                                        synchronized (mainPane.lock) {
                                            mainPane.act_test_vars.add(v);
                                        }
                                        break;
                                    }
                                    case URL: {
                                        // works
                                        if (!isRequest) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String header_0 = messageInfo.getUrlHeader();

                                        pattern = mop.action == Utils.MessageOperationActions.SAVE ?
                                                Pattern.compile(mop.what + "=[^& ]*(?=(&| ))") :
                                                Pattern.compile(mop.what);

                                        matcher = pattern.matcher(header_0);
                                        String value = "";

                                        if (matcher.find()) {
                                            String matched = matcher.group();
                                            value = mop.action == Utils.MessageOperationActions.SAVE ?
                                                    matched.split("=")[1] :
                                                    matched;

                                            Var v = new Var();
                                            v.name = mop.save_as;
                                            v.isMessage = false;
                                            v.value = value;
                                            synchronized (mainPane.lock) {
                                                mainPane.act_test_vars.add(v);
                                            }
                                        }
                                        break;
                                    }
                                }
                                break;
                        }
                    }
                }

                if (op.processed_message != null) {
                    if (isRequest) {
                        messageInfo.setRequest(op.processed_message);
                    } else {
                        messageInfo.setResponse(op.processed_message);
                    }
                    if (op.processed_message_service != null) {
                        // TODO: check if ok to remove
                        //messageInfo.setHttpService(op.processed_message_service);
                    }
                }
            } catch (StackOverflowError e) {
                e.printStackTrace();
            }
        }
        return op;
    }

    /**
     * Returns the adding of a message operation, decides if the value to be inserted/edited should be a variable or
     * a typed value and return it
     *
     * @param m the message operation which has to be examined
     * @return the adding to be used in add/edit
     * @throws ParsingException if the variable name is not valid or the variable has not been initiated
     */
    private String getAdding(MessageOperation m) throws ParsingException {
        if (!m.use.isEmpty()) {
            return getVariableByName(m.use, mainPane).value;
        } else {

            return m.to;
        }
    }

    /**
     * Tells the lock on the Execute Actives process to resume the execution
     */
    private void resume() {
        // Resume the execution thread
        synchronized (mainPane.waiting) {
            mainPane.waiting.notify();
        }
    }

    private void log_message(boolean isRequest, IInterceptedProxyMessage message) {
        mainPane.act_active_op.log_messages.add(message);
    }
}
