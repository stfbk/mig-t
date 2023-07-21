package migt;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static migt.Tools.getVariableByName;

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
     * Given an operation, and a message, execute the Message operations contained in the operation
     *
     * @param op          the operation containing the message operations
     * @param messageInfo the message
     * @param isRequest   true if the message is a request
     * @return the updated Operation with the result
     * @throws ParsingException if parsing of names is not successfull
     */
    public static Operation executeMessageOps(Operation op,
                                              HTTPReqRes messageInfo,
                                              boolean isRequest) throws ParsingException {
        for (MessageOperation mop : op.getMessageOerations()) {
            List<String> splitted;
            Pattern pattern;
            Matcher matcher;
            byte[] new_message;
            try {
                if (mop.type == MessageOperation.MessageOpType.GENERATE_POC) {
                    if (!isRequest) {
                        throw new ParsingException("Invalid POC generation, message should be a request");
                    }

                    if (!mop.template.equals("csrf")) {
                        continue; // other templates not supported yet
                    }

                    String poc = Tools.generate_CSRF_POC(messageInfo, helpers);

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
                                if (getAdding(mop, op.api.vars) == null | getAdding(mop, op.api.vars).equals("")) {
                                    // TODO: should raise exception or set operation not applicable?
                                    break;
                                }
                                switch (mop.from) {
                                    case HEAD: {
                                        messageInfo.addHeadParameter(isRequest, mop.what, getAdding(mop, op.api.vars));
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                    }
                                    case BODY: {
                                        String tmp = new String(messageInfo.getBody(isRequest));
                                        tmp = tmp + getAdding(mop, op.api.vars);
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
                                            newHeader_0 = before + getAdding(mop, op.api.vars) + after;
                                            found = true;
                                        }
                                        messageInfo.setUrlHeader(newHeader_0);
                                        op.processed_message = messageInfo.getMessage(isRequest, helpers);
                                        break;
                                }
                                break;

                            case EDIT:
                                op.processed_message = Tools.editMessageParam(
                                        helpers,
                                        mop.what,
                                        mop.from,
                                        messageInfo,
                                        isRequest,
                                        getAdding(mop, op.api.vars),
                                        true);
                                break;

                            case EDIT_REGEX:
                                op.processed_message = Tools.editMessage(
                                        helpers,
                                        mop.what,
                                        mop,
                                        messageInfo,
                                        isRequest,
                                        getAdding(mop, op.api.vars));
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
                                        if (mop.action == MessageOperation.MessageOperationActions.SAVE) {
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
                                        op.api.vars.add(v);
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
                                        op.api.vars.add(v);
                                        break;
                                    }
                                    case URL: {
                                        // works
                                        if (!isRequest) {
                                            throw new ParsingException("Searching URL in response");
                                        }
                                        String header_0 = messageInfo.getUrlHeader();

                                        pattern = mop.action == MessageOperation.MessageOperationActions.SAVE ?
                                                Pattern.compile(mop.what + "=[^& ]*(?=(&| ))") :
                                                Pattern.compile(mop.what);

                                        matcher = pattern.matcher(header_0);
                                        String value = "";

                                        if (matcher.find()) {
                                            String matched = matcher.group();
                                            value = mop.action == MessageOperation.MessageOperationActions.SAVE ?
                                                    matched.split("=")[1] :
                                                    matched;

                                            Var v = new Var();
                                            v.name = mop.save_as;
                                            v.isMessage = false;
                                            v.value = value;
                                            op.api.vars.add(v);
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
    private static String getAdding(MessageOperation m, List<Var> vars) throws ParsingException {
        if (!m.use.isEmpty()) {
            return getVariableByName(m.use, vars).value;
        } else {

            return m.to;
        }
    }

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
     * @param proxy_message    An
     *                         <code>IInterceptedProxyMessage</code> object that extensions can use to
     *                         query and update details of the message, and control whether the message
     *                         should be intercepted and displayed to the user for manual review or
     */
    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxy_message) {
        String port = proxy_message.getListenerInterface().split(":")[1];
        IHttpRequestResponse messageInfo = proxy_message.getMessageInfo();

        if (mainPane.ACTIVE_ENABLED) {
            if (!port.equals(mainPane.act_active_op.session_port)) {
                return;
            }

            log_message(messageIsRequest, proxy_message);

            MessageType msg_type = null;
            try {
                msg_type = MessageType.getFromList(mainPane.messageTypes,
                        mainPane.act_active_op.getMessageType());
            } catch (Exception e) {
                e.printStackTrace();
                mainPane.act_active_op.applicable = false;
            }

            boolean matchMessage = false;

            try {
                /* If the response message name is searched, the getByResponse will be true.
                 * so i have to search for the request, and then evaluate the response*/
                if (msg_type.getByResponse) {
                    if (!messageIsRequest) {
                        matchMessage = Tools.executeChecks(msg_type.checks,
                                new HTTPReqRes(messageInfo, helpers, true),
                                true, mainPane.act_active_op.api.vars);
                    }
                } else if (msg_type.getByRequest) {
                    if (!messageIsRequest) {
                        matchMessage = Tools.executeChecks(msg_type.checks,
                                new HTTPReqRes(messageInfo, helpers, false),
                                false, mainPane.act_active_op.api.vars);
                    }
                } else {
                    if (messageIsRequest == msg_type.isRequest) {
                        matchMessage = Tools.executeChecks(msg_type.checks,
                                new HTTPReqRes(messageInfo, helpers, msg_type.isRequest),
                                msg_type.isRequest, mainPane.act_active_op.api.vars);
                    }
                }
            } catch (ParsingException e) {
                mainPane.act_active_op.applicable = false;
                return;
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

                // If the operation's action is an intercept
                if (Objects.requireNonNull(mainPane.act_active_op.getAction()) == Operation.Action.INTERCEPT) {
                    try {
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
                                            mainPane.act_active_op.then == Operation.Then.DROP) {
                                        proxy_message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        mainPane.act_active_op.applicable = false;
                    }
                }
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

        mainPane.act_active_op.helpers = helpers;
        mainPane.act_active_op.api.message = message;
        mainPane.act_active_op.api.is_request = msg_type.isRequest;
        mainPane.act_active_op.execute();

        // if message has been edited inside operation update the value
        if (mainPane.act_active_op.processed_message != null) {
            //TODO: remove processed_message in future
            if (msg_type.isRequest) {
                messageInfo.setRequest(mainPane.act_active_op.processed_message);
            } else {
                messageInfo.setResponse(mainPane.act_active_op.processed_message);
            }
        } else {
            if (msg_type.isRequest) {
                messageInfo.setRequest(message.getMessage(message.isRequest, helpers));
            } else {
                messageInfo.setResponse(message.getMessage(message.isRequest, helpers));
            }
        }
        resume();
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
