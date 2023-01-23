package burp;

import samlraider.application.SamlTabController;
import samlraider.helpers.XMLHelpers;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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
    private boolean isOauthflow = false;

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
        return "Plugin Draft";
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
                    case "oauth request":
                        if (messageIsRequest && isOauthflow) {
                            matchMessage = true;
                        }
                        break;
                    case "oauth response":
                        if (!messageIsRequest && isOauthflow) {
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
                    if (!isOauthflow & Utils.isAuthRequest(
                            helpers.analyzeRequest(messageInfo.getRequest()).getHeaders().get(0))) isOauthflow = true;

                    try {
                        switch (mainPane.act_active_op.getMessageType()) {
                            case "request":
                                if (matchMessage) {
                                    processMatchedMsg(messageInfo, true, false);
                                }
                                break;
                            case "response":
                                if (matchMessage) {
                                    processMatchedMsg(messageInfo, false, true);
                                }
                                break;
                            case "oauth request":
                                if (matchMessage) {
                                    processMatchedMsg(messageInfo, true, false);
                                }
                                break;
                            case "oauth response":
                                if (matchMessage) {
                                    processMatchedMsg(messageInfo, false, true);
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
                                            processMatchedMsg(messageInfo, false, true);
                                        }
                                    }
                                } else if (msg_type.getByRequest) {
                                    if (!messageIsRequest) {
                                        if (matchMessage) {
                                            processMatchedMsg(messageInfo, true, false);
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
                                        isOauthflow ? -1 : 1, // this is not good
                                        helpers,
                                        mainPane.messageTypes);
                            } catch (ParsingException e) {
                                e.printStackTrace();
                                mainPane.act_active_op.applicable = false;
                                resume();
                            }

                            mainPane.act_active_op.applicable = results.get(3);
                            if (mainPane.act_active_op.applicable) {
                                mainPane.act_active_op.passed = results.get(0);
                                if (!mainPane.act_active_op.passed) resume();
                                mainPane.act_active_op.act_matched++;
                            }
                            resume();
                        }
                    }
                    break;
            }

        }
        if (mainPane.recording) {
            if (!messageIsRequest) { // non toglierlo, non so perchè ma serve
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

    private void processMatchedMsg(IHttpRequestResponse messageInfo, boolean isRequest, boolean isResponse) {
        messageInfo.setHighlight("red");
        mainPane.act_active_op = executeOperation(mainPane.act_active_op,
                messageInfo,
                isRequest);
        if (mainPane.act_active_op.processed_message != null) {
            if (isRequest) messageInfo.setRequest(mainPane.act_active_op.processed_message);
            else messageInfo.setResponse(mainPane.act_active_op.processed_message);
        }
        resume();
    }

    private void processMatchedMsg(MessageType msg_type,
                                   IHttpRequestResponse messageInfo) {
        messageInfo.setHighlight("red");
        mainPane.act_active_op = executeOperation(mainPane.act_active_op,
                messageInfo,
                msg_type.isRequest);
        if (mainPane.act_active_op.processed_message != null) {
            if (msg_type.isRequest) {
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
    private Operation executeOperation(Operation op, IHttpRequestResponse messageInfo, boolean isRequest) {
        if (!op.preconditions.isEmpty()) {
            HTTPReqRes message = new HTTPReqRes(messageInfo, helpers, isRequest);
            try {
                op.applicable = Tools.executeChecks(op.preconditions,
                        message,
                        helpers,
                        isRequest);
                if (!op.applicable) return op;
            } catch (ParsingException e) {
                op.applicable = false;
                e.printStackTrace();
                return op;
            }
        }

        if (isRequest) {
            if (!op.replace_request_name.equals("")) {
                try {
                    op.applicable = true;
                    op.processed_message = getVariableByName(op.replace_request_name).message;
                    op.processed_message_service = getVariableByName(op.replace_request_name).service_info;
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
                    op.processed_message = getVariableByName(op.replace_response_name).message;
                    op.processed_message_service = getVariableByName(op.replace_response_name).service_info;
                    //return op;
                } catch (ParsingException e) {
                    e.printStackTrace();
                    op.applicable = false;
                    return op;
                }
            }
        }

        try {
            op.applicable = true;
            op = executeMessageOps(op, messageInfo, isRequest);

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
            v.service_info = messageInfo.getHttpService();
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
                                       IHttpRequestResponse messageInfo,
                                       boolean isRequest) throws ParsingException {
        for (MessageOperation mop : op.getMessageOerations()) {
            List<String> splitted;
            Pattern pattern;
            Matcher matcher;
            byte[] new_message;
            boolean decode = false;
            String decoded_param = "";
            String original_cert = "";
            XMLHelpers xmlHelpers = new XMLHelpers();

            try {
                if (!mop.decode_param.equals("")) {
                    decode = true;

                    decoded_param = Encoding.decodeParam(
                            helpers, mop.from, mop.encodings, messageInfo, isRequest, mop.decode_param);
                }
                if (mop.self_sign | mop.remove_signature) {
                    //Remove signatures
                    Document document = null;
                    try {
                        document = xmlHelpers.getXMLDocumentOfSAMLMessage(decoded_param);
                        original_cert = xmlHelpers.getCertificate(document.getDocumentElement());
                        if (original_cert == null) {
                            System.out.println("SAML Certificate not found in decoded parameter \"" + mop.decode_param + "\"");
                            op.applicable = false;
                        }
                        decoded_param = SamlTabController.removeSignature_edit(decoded_param);

                    } catch (SAXException e) {
                        e.printStackTrace();
                    }
                }

                if (!mop.use.equals("")) {
                    Var v = getVariableByName(mop.use);
                    if (!v.isMessage) {
                        mop.value = v.value;
                    } else {
                        throw new ParsingException("Error while using variable, expected text var, got message var");
                    }
                }

                switch (mop.type) {
                    case XML: {
                        if (!decode) {
                            throw new ParsingException("cannot found decoded parameter");
                        }
                        switch (mop.xml_action) {
                            case ADD_TAG:
                                decoded_param = XML.addTag(decoded_param,
                                        mop.xml_tag,
                                        mop.xml_action_name,
                                        mop.value,
                                        mop.xml_occurrency);
                                break;
                            case ADD_ATTR:
                                decoded_param = XML.addTagAttribute(decoded_param,
                                        mop.xml_tag,
                                        mop.xml_action_name,
                                        mop.value,
                                        mop.xml_occurrency);
                                break;
                            case EDIT_TAG:
                                decoded_param = XML.editTagValue(decoded_param,
                                        mop.xml_action_name,
                                        mop.value,
                                        mop.xml_occurrency);
                                break;
                            case EDIT_ATTR:
                                decoded_param = XML.editTagAttributes(decoded_param,
                                        mop.xml_tag,
                                        mop.xml_action_name,
                                        mop.value,
                                        mop.xml_occurrency);
                                break;
                            case REMOVE_TAG:
                                decoded_param = XML.removeTag(decoded_param,
                                        mop.xml_action_name,
                                        mop.xml_occurrency);
                                break;
                            case REMOVE_ATTR:
                                decoded_param = XML.removeTagAttribute(decoded_param,
                                        mop.xml_tag,
                                        mop.xml_action_name,
                                        mop.xml_occurrency);
                                break;
                            case SAVE_TAG: {
                                String to_save = XML.getTagValaue(decoded_param,
                                        mop.xml_action_name,
                                        mop.xml_occurrency);
                                Var v = new Var();
                                v.name = mop.save_as;
                                v.isMessage = false;
                                v.value = to_save;
                                synchronized (mainPane.lock) {
                                    mainPane.act_test_vars.add(v);
                                }

                                break;
                            }
                            case SAVE_ATTR:
                                String to_save = XML.getTagAttributeValue(decoded_param,
                                        mop.xml_tag, mop.xml_action_name,
                                        mop.xml_occurrency);
                                Var v = new Var();
                                v.name = mop.save_as;
                                v.isMessage = false;
                                v.value = to_save;
                                synchronized (mainPane.lock) {
                                    mainPane.act_test_vars.add(v);
                                }
                                break;
                        }
                        break;
                    }
                    case JWT: {
                        op.jwt = new JWT();
                        if (mop.isRawJWT) {
                            op.jwt.parseJWT_string(decoded_param);
                        } else {
                            op.jwt.parseJWT(decoded_param);
                        }

                        switch (mop.jwt_action) {
                            case REMOVE:
                                op.jwt.removeClaim(mop.jwt_section, mop.what);
                                break;
                            case EDIT:
                            case ADD:
                                op.jwt.editAddClaim(mop.jwt_section, mop.what, mop.value);
                                break;
                            case SAVE:
                                Var v = new Var();
                                v.name = mop.save_as;
                                v.isMessage = false;
                                v.value = op.jwt.getClaim(mop.jwt_section, mop.what);
                                synchronized (mainPane.lock) {
                                    mainPane.act_test_vars.add(v);
                                }
                                break;
                        }

                        decoded_param = mop.isRawJWT ?
                                op.jwt.buildJWT_string() :
                                op.jwt.buildJWT();
                        break;
                    }
                    case TXT: {
                        Pattern p = Pattern.compile(mop.txt_action_name);
                        Matcher m = p.matcher(decoded_param);

                        if (mop.txt_action == null) {
                            throw new ParsingException("txt action not specified");
                        }

                        switch (mop.txt_action) {
                            case REMOVE:
                                decoded_param = m.replaceAll("");

                                break;
                            case EDIT:
                                decoded_param = m.replaceAll(mop.value);

                                break;
                            case ADD:
                                while (m.find()) {
                                    int index = m.end();
                                    String before = decoded_param.substring(0, index);
                                    String after = decoded_param.substring(index);
                                    decoded_param = before + mop.value + after;
                                    break;
                                }
                                break;
                            case SAVE:
                                String val = "";
                                while (m.find()) {
                                    val = m.group();
                                    break;
                                }

                                Var v = new Var();
                                v.name = mop.save_as;
                                v.isMessage = false;
                                v.value = val;
                                synchronized (mainPane.lock) {
                                    mainPane.act_test_vars.add(v);
                                }
                                break;
                        }
                        break;
                    }
                    case GENERATE_POC: {
                        //TODO: Finish
                        if (!isRequest) {
                            throw new ParsingException("Invalid POC generation, message should be a request");
                        }

                        if (!mop.template.equals("csrf")){
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
                    }
                    default: // HTTP standard
                        if (mop.action != null) {
                            switch (mop.action) {
                                case REMOVE_PARAMETER:
                                    switch (mop.from) {
                                        case URL:
                                            // Works
                                            if (!isRequest) {
                                                throw new ParsingException("Searching URL in response");
                                            }
                                            List<String> parts = Utils.splitMessage(messageInfo, helpers, isRequest);
                                            pattern = Pattern.compile("&?" + mop.what + "=[^& ]*((?=&)|(?= ))");
                                            matcher = pattern.matcher(parts.get(0));
                                            String new_url = matcher.replaceFirst("");

                                            new_message = Utils.setUrl(new_url, messageInfo, helpers, isRequest);

                                            op.processed_message = new_message;
                                            break;
                                        case HEAD:
                                            List<String> headers = Utils.getHeaders(messageInfo, isRequest, helpers);
                                            headers = Utils.removeHeadParameter(headers, mop.what);
                                            byte[] message = helpers.buildHttpMessage(
                                                    headers,
                                                    Utils.getBody(messageInfo, isRequest, helpers));

                                            op.processed_message = message;
                                            break;
                                        case BODY:
                                            // Works
                                            splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                                            pattern = Pattern.compile(mop.what);
                                            matcher = pattern.matcher(splitted.get(2));
                                            splitted.set(2, matcher.replaceAll(""));

                                            List<String> head = Utils.getHeaders(messageInfo, isRequest, helpers);
                                            //Automatically update content-lenght
                                            op.processed_message = helpers.buildHttpMessage(
                                                    head,
                                                    helpers.stringToBytes(splitted.get(2)));
                                            break;
                                    }
                                    break;

                                case ADD:
                                    if (getAdding(mop) == null | getAdding(mop).equals("")) {
                                        break;
                                    }
                                    switch (mop.from) {
                                        case HEAD: {
                                            List<String> headers = Utils.getHeaders(messageInfo, isRequest, helpers);
                                            headers = Utils.addHeadParameter(headers, mop.what, getAdding(mop));
                                            byte[] message = helpers.buildHttpMessage(
                                                    headers,
                                                    Utils.getBody(messageInfo, isRequest, helpers));

                                            op.processed_message = message;
                                            break;
                                        }
                                        case BODY: {
                                            // Works
                                            splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                                            String tmp = splitted.get(2);
                                            tmp = tmp + getAdding(mop);
                                            splitted.set(2, tmp);

                                            List<String> head = Utils.getHeaders(messageInfo, isRequest, helpers);
                                            //Automatically update content-lenght
                                            op.processed_message = helpers.buildHttpMessage(
                                                    head,
                                                    helpers.stringToBytes(splitted.get(2)));
                                            break;
                                        }
                                        case URL:
                                            // Works
                                            if (!isRequest) {
                                                throw new ParsingException("Searching URL in response");
                                            }

                                            List<String> parts = Utils.splitMessage(messageInfo, helpers, isRequest);
                                            String header_0 = parts.get(0);

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

                                            new_message = Utils.setUrl(newHeader_0, messageInfo, helpers, isRequest);
                                            op.processed_message = new_message;
                                            break;
                                    }
                                    break;

                                case EDIT:
                                    op.processed_message = Utils.editMessageParam(
                                            helpers,
                                            mop.what,
                                            mop,
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
                                            getAdding(mop),
                                            true);
                                    break;

                                case REMOVE_MATCH_WORD:
                                    switch (mop.from) {
                                        case HEAD: {
                                            // Works
                                            splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                                            pattern = Pattern.compile(mop.what);
                                            matcher = pattern.matcher(splitted.get(1));
                                            splitted.set(1, matcher.replaceAll(""));

                                            byte[] message = Utils.buildMessage(splitted, helpers);

                                            op.processed_message = message;
                                            break;
                                        }
                                        case BODY: {
                                            // Works
                                            splitted = Utils.splitMessage(messageInfo, helpers, isRequest);

                                            pattern = Pattern.compile(mop.what);
                                            matcher = pattern.matcher(splitted.get(2));
                                            splitted.set(2, matcher.replaceAll(""));

                                            List<String> head = Utils.getHeaders(messageInfo, isRequest, helpers);
                                            //Automatically update content-lenght
                                            op.processed_message = helpers.buildHttpMessage(
                                                    head,
                                                    helpers.stringToBytes(splitted.get(2)));
                                            break;
                                        }
                                        case URL:
                                            // Works
                                            if (!isRequest) {
                                                throw new ParsingException("Searching URL in response");
                                            }
                                            List<String> parts = Utils.splitMessage(messageInfo, helpers, isRequest);
                                            String header_0 = parts.get(0);

                                            pattern = Pattern.compile(mop.what);
                                            matcher = pattern.matcher(header_0);
                                            String newHeader_0 = matcher.replaceFirst("");

                                            new_message = Utils.setUrl(newHeader_0, messageInfo, helpers, isRequest);
                                            op.processed_message = new_message;
                                            break;
                                    }
                                    break;

                                case SAVE:
                                case SAVE_MATCH:
                                    switch (mop.from) {
                                        case HEAD: {
                                            String value = "";
                                            if (mop.action == Utils.MessageOperationActions.SAVE) {
                                                List<String> headers = Utils.getHeaders(messageInfo, isRequest, helpers);
                                                value = Utils.getHeadParameterValue(headers, mop.what).trim();
                                            } else {
                                                splitted = Utils.splitMessage(messageInfo, helpers, isRequest);
                                                pattern = Pattern.compile(mop.what);
                                                matcher = pattern.matcher(splitted.get(1));
                                                value = "";
                                                while (matcher.find()) {
                                                    value = matcher.group();
                                                    break;
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
                                            // Works
                                            splitted = Utils.splitMessage(messageInfo, helpers, isRequest);
                                            String tmp = splitted.get(2);
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
                                            List<String> parts = Utils.splitMessage(messageInfo, helpers, isRequest);
                                            String header_0 = parts.get(0);

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


                if (mop.self_sign && !decoded_param.equals("")) {
                    //re-sign

                    decoded_param = SamlTabController.resignAssertion_edit(decoded_param, original_cert);
                    //decoded_param = SamlTabController.resignMessage_edit(decoded_param, original_cert);

                }

                if (decode && !decoded_param.equals("")) {
                    // encode the edited param and substitute it in the right place

                    Collections.reverse(mop.encodings); // Set the right order for encoding
                    String encoded = Encoding.encode(mop.encodings, decoded_param, helpers);

                    op.processed_message = Utils.editMessageParam(helpers,
                            mop.decode_param, mop, messageInfo, isRequest, encoded, true);
                }
                if (op.processed_message != null) {
                    if (isRequest) {
                        messageInfo.setRequest(op.processed_message);
                    } else {
                        messageInfo.setResponse(op.processed_message);
                    }
                    if (op.processed_message_service != null) {
                        messageInfo.setHttpService(op.processed_message_service);
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
            return getVariableByName(m.use).value;
        } else {

            return m.to;
        }
    }

    /**
     * Given a name, returns the corresponding variable
     *
     * @param name the name of the variable
     * @return the Var object
     * @throws ParsingException if the variable cannot be found
     */
    private Var getVariableByName(String name) throws ParsingException {
        synchronized (mainPane.lock) {
            for (Var act : mainPane.act_test_vars) {
                if (act.name.equals(name)) {
                    return act;
                }
            }
        }
        throw new ParsingException("variable not defined");
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
