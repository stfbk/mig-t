package burp;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class with methods to process messages and execute tests
 *
 * @author Matteo Bitussi
 */
public class Tools {
    /**
     * Function that execute the given passive test.
     *
     * @param test        a <Code>Test</Code> element, it has to be a passive test
     * @param messageList a list of <code>HTTPReqRes</code> messages
     * @param helpers     an istance of <code>IExtensionHelpers</code>
     * @param msg_types   the message types used by the test
     * @return true if a test is passed, false otherwise
     */
    public static boolean executePassiveTest(Test test,
                                             List<HTTPReqRes> messageList,
                                             IExtensionHelpers helpers,
                                             List<MessageType> msg_types) {
        int i, j;
        boolean res = true;
        boolean actisreq = false;
        boolean actisresp = false;

        int first_message_index = getInitMessageIndex(messageList, helpers);

        for (i = 0; i < messageList.size(); i++) {
            j = 0;
            while (j < test.operations.size() && res) {
                actisreq = false;
                actisresp = false;

                Operation currentOP = test.operations.get(j);

                List<Boolean> result = null;
                try {
                    result = executePassiveOperation(currentOP, messageList.get(i), i, first_message_index, helpers, msg_types);
                } catch (ParsingException e) {
                    e.printStackTrace();
                    res = false;
                    currentOP.applicable = false;
                    break;
                }
                res = result.get(0);
                actisreq = result.get(1);
                actisresp = result.get(2);
                currentOP.applicable = result.get(3);
                j++;
            }
            if (!res) {
                test.operations.get(--j).matchedMessages.add(new Operation.MatchedMessage(messageList.get(i), i, actisreq, actisresp, true));
                break;
            }
        }

        for (Operation op : test.operations) {
            if (!op.applicable) {
                res = false;
                test.applicable = false;
                break;
            }
        }

        return res;
    }

    /**
     * Còass that executes a passive operation
     *
     * @param op                  The operation to be executed
     * @param message             the message to be used in the execution
     * @param messageIndex        the index of that message w.r.t. the list of messages ( if present ) otherwise write 0
     * @param first_message_index the index of the first OAuth message, to enable the filtering for oauth messages
     * @param helpers             An istance of the IExtensionHelpers
     * @param msg_types           the list of msg_types available
     * @return a list of booleans, containing in order: the result of the operation, if the actual message is a request,
     * if the actual message is a response, if the operation is applicable
     * <p>
     * Note that this function is used also to validate active checks.
     */
    public static List<Boolean> executePassiveOperation(Operation op,
                                                        HTTPReqRes message,
                                                        int messageIndex,
                                                        int first_message_index,
                                                        IExtensionHelpers helpers,
                                                        List<MessageType> msg_types) throws ParsingException {
        boolean res = true;
        boolean actisreq = false;
        boolean actisresp = false;
        switch (op.getMessageType()) {
            case "request":
                op.applicable = true;
                actisreq = true;
                res = processOperation(op, message, messageIndex, helpers, true, false);
                break;
            case "response":
                op.applicable = true;
                actisreq = true;
                res = processOperation(op, message, messageIndex, helpers, false, true);
                break;
            case "oauth request":
                if (messageIndex >= first_message_index) {
                    op.applicable = true;
                    actisreq = true;
                    res = processOperation(op, message, messageIndex, helpers, true, false);
                }
                break;
            case "oauth response":
                if (messageIndex >= first_message_index) {
                    op.applicable = true;
                    actisreq = true;
                    res = processOperation(op, message, messageIndex, helpers, false, true);
                }
                break;
            default:
                try {
                    MessageType msg_type = MessageType.getFromList(msg_types, op.getMessageType());

                    /* If the response message name is searched, the getByResponse will be true.
                     * so messageIndex have to search for the request, and then evaluate the response*/
                    Boolean matchedMessage = false;

                    if (msg_type.getByResponse) {
                        if (msg_type.isRegex) {
                            matchedMessage = Tools.findInMessage(msg_type.messageSection,
                                    msg_type.regex,
                                    message,
                                    helpers,
                                    true);
                        } else {
                            matchedMessage = Tools.executeChecks(msg_type.checks,
                                    message,
                                    helpers,
                                    true);
                        }
                        if (matchedMessage) {
                            op.applicable = true;
                            actisreq = false;
                            actisresp = true;

                            res = processOperation(op, message, messageIndex, helpers, false, true);
                        }
                    } else if (msg_type.getByRequest) {
                        if (msg_type.isRegex) {
                            matchedMessage = Tools.findInMessage(msg_type.messageSection,
                                    msg_type.regex,
                                    message,
                                    helpers, false);
                        } else {
                            matchedMessage = Tools.executeChecks(msg_type.checks,
                                    message,
                                    helpers, false);
                        }
                        if (matchedMessage) {
                            op.applicable = true;
                            actisreq = false;
                            actisresp = true;

                            res = processOperation(op, message, messageIndex, helpers, true, false);
                        }
                    } else {
                        if (msg_type.isRegex) {
                            matchedMessage = Tools.findInMessage(msg_type.messageSection,
                                    msg_type.regex,
                                    message,
                                    helpers,
                                    msg_type.isRequest);
                        } else {
                            matchedMessage = Tools.executeChecks(msg_type.checks,
                                    message,
                                    helpers,
                                    msg_type.isRequest);
                        }
                        if (matchedMessage) {
                            op.applicable = true;
                            actisreq = msg_type.isRequest;
                            actisresp = !msg_type.isRequest;

                            res = processOperation(op, message, messageIndex, helpers, msg_type.isRequest, !msg_type.isRequest);
                        }
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
        }
        List<Boolean> tmp = new ArrayList<>();
        tmp.add(res);
        tmp.add(actisreq);
        tmp.add(actisresp);
        tmp.add(op.applicable);
        return tmp;
    }

    /**
     * Function that processes an operation over a message
     *
     * @param currentOP     the <code>Operation</code> to be processed
     * @param act_message   the message over which the operation has to be executed
     * @param message_index the index of the <code>act_message</code> in the messages list
     * @param helpers       An istance of the helpers
     * @param request       set true if the request has to be processed
     * @param response      set true if the response has to be processed
     * @return the result of the operation
     */
    public static boolean processOperation(Operation currentOP,
                                           HTTPReqRes act_message,
                                           int message_index,
                                           IExtensionHelpers helpers,
                                           boolean request,
                                           boolean response) throws ParsingException {
        String decode_param = currentOP.decode_param;
        String decoded_param = "";

        HTTPReqRes message = null;
        boolean res = true;

        try {
            message = (HTTPReqRes) act_message.clone();
        } catch (CloneNotSupportedException e) {
            e.printStackTrace();
            currentOP.applicable = false;
            return false;
        }

        if (!decode_param.equals("")) {
            try {
                if (!currentOP.decode_param.equals("")) {

                    decoded_param = Encoding.decodeParam(
                            helpers,
                            currentOP.getMessageSection(),
                            currentOP.encodings,
                            act_message,
                            request,
                            decode_param);

                    if (!currentOP.isRegex) {
                        throw new ParsingException("Checks cannot be executed on decode parameters");
                    }

                    Pattern p = Pattern.compile(currentOP.getRegex());
                    Matcher m = p.matcher(decoded_param);

                    boolean match = m.find();

                    if (request)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message,
                                        message_index,
                                        true,
                                        false,
                                        false));
                    if (!request || response)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message,
                                        message_index,
                                        false,
                                        true,
                                        false));

                    return match;
                }
            } catch (StackOverflowError e) {
                e.printStackTrace();
                currentOP.applicable = false;
                return false;
            }
        }

        if (currentOP.isRegex) {
            try {
                res = !request || Tools.findInMessage(
                        currentOP.getMessageSection(), currentOP.getRegex(), message, helpers, true);
                if (!res) {
                    if (request)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message, message_index, true, false, true));
                    return false;
                }
                res = !response || Tools.findInMessage(
                        currentOP.getMessageSection(), currentOP.getRegex(), message, helpers, false);
                if (!res) {
                    if (response)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message, message_index, false, true, true));
                    return false;
                }

                if (request)
                    currentOP.matchedMessages.add(
                            new Operation.MatchedMessage(
                                    message, message_index, true, false, false));
                if (response)
                    currentOP.matchedMessages.add(
                            new Operation.MatchedMessage(
                                    message, message_index, false, true, false));
            } catch (ParsingException e) {
                currentOP.applicable = false;
                System.err.println(e);
            }

        } else {
            try {
                res = !request || Tools.executeChecks(
                        currentOP.getChecks(), message, helpers, true);
                if (!res) {
                    if (request)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message, message_index, true, false, true));
                    return false;
                }
                res = !response || Tools.executeChecks(
                        currentOP.getChecks(), message, helpers, false);
                if (!res) {
                    if (response)
                        currentOP.matchedMessages.add(
                                new Operation.MatchedMessage(
                                        message, message_index, false, true, true));
                    return false;
                }

                if (request)
                    currentOP.matchedMessages.add(
                            new Operation.MatchedMessage(
                                    message, message_index, true, false, false));
                if (response)
                    currentOP.matchedMessages.add(
                            new Operation.MatchedMessage(
                                    message, message_index, false, true, false));
            } catch (ParsingException e) {
                currentOP.applicable = false;
                System.err.println(e);
            }
        }

        return res;
    }

    /**
     * Function that check a regex over a given message and section
     *
     * @param section the section of the message to be checked with the regex
     * @param regex   the regex
     * @param message the message to be checked
     * @param helpers an istance of the helpers
     * @return the result of the check, if the regex matches 1 or more time it returns true
     */
    public static boolean findInMessage(Utils.MessageSection section,
                                        String regex,
                                        HTTPReqRes message,
                                        IExtensionHelpers helpers,
                                        boolean isRequest) throws ParsingException {
        int occ = 0;

        Pattern pattern;
        Matcher matcher;

        switch (section) {
            case URL:
                if (!isRequest) {
                    throw new ParsingException("Searching URL in response");
                }
                String url = message.getRequest_url();
                pattern = Pattern.compile(regex);
                matcher = pattern.matcher(url);

                while (matcher.find()) {
                    occ++;
                }
                break;

            case HEAD:
                pattern = Pattern.compile(regex);
                List<String> header = isRequest ? helpers.analyzeRequest(message.getRequest()).getHeaders() :
                        helpers.analyzeResponse(message.getResponse()).getHeaders();

                String headersString = getAllHeaders(header);

                matcher = pattern.matcher(headersString);

                while (matcher.find()) {
                    occ++;
                }
                break;

            case BODY:
                pattern = Pattern.compile(regex, Pattern.DOTALL);
                int index = isRequest ?
                        helpers.analyzeRequest(message.getRequest()).getBodyOffset()
                        : helpers.analyzeResponse(message.getResponse()).getBodyOffset();

                byte[] body = isRequest ?
                        Arrays.copyOfRange(message.getRequest(), index, message.getRequest().length)
                        : Arrays.copyOfRange(message.getResponse(), index, message.getResponse().length);

                String rawBody = new String(body);
                matcher = pattern.matcher(rawBody);

                while (matcher.find()) {
                    occ++;
                }
                break;

            case RAW:
                String raw_msg = isRequest ?
                        new String(message.getRequest(), StandardCharsets.UTF_8) :
                        new String(message.getResponse(), StandardCharsets.UTF_8);

                pattern = Pattern.compile(regex, Pattern.DOTALL);
                matcher = pattern.matcher(raw_msg);

                while (matcher.find()) {
                    occ++;
                }
                break;

            default:
                System.out.println("No right message section selected");
        }

        return (occ > 0);
    }

    /**
     * Function that given a list of headers, concatenate them in a single string
     *
     * @param headers the list of headers
     * @return the string
     */
    public static String getAllHeaders(List<String> headers) {
        StringBuilder out = new StringBuilder();
        for (Object o : headers) {
            out.append(o.toString());
            out.append("\n");
        }
        return out.toString();
    }

    /**
     * This method retrieves Authorization Grant (Response) - Start of OAuth flow
     *
     * @param messageList the list of <code>HTTPReqRes</code> messages over search to
     * @param helpers     an instance of the helpers
     * @return the index of the Authorization GRant message in the list of messages
     */
    public static int getInitMessageIndex(List<HTTPReqRes> messageList, IExtensionHelpers helpers) {
        int result = -1;
        for (int i = 0; i < messageList.size() && result < 0; i++)
            if (helpers.bytesToString(messageList.get(i).getResponse()).contains("response_type"))
                result = i;

        return result;
    }

    /**
     * This method checks if the give message is an Authorization Grant Response
     *
     * @param messageInfo the message to check
     * @param helpers     an istance of the helpers
     * @return a boolean true or false
     */
    public static boolean isFirstMessage(HTTPReqRes messageInfo, IExtensionHelpers helpers) {
        return helpers.bytesToString(messageInfo.getResponse()).contains("response_type=code");
    }

    /**
     * This method checks if the messageInfo is the last message of the OAuth flow
     *
     * @param messageInfo the message
     * @param helpers     the helpers
     * @return a boolean true or false
     */
    public static boolean isLastMessage(HTTPReqRes messageInfo, IExtensionHelpers helpers) {
        String rawBody = helpers.bytesToString(messageInfo.getResponse());
        boolean result = false;
        List<IParameter> requestParams = helpers.analyzeRequest(messageInfo.getRequest()).getParameters();
        for (int i = 0; i < requestParams.size(); i++) {

            if (requestParams.get(i).getName().equals("code")) {
                result = true;
            }
        }
        //return result && rawBody.contains("access_token");
        return result;
    }

    /**
     * This function execute a list of checks over a message, returning true if all the checks are successful
     *
     * @param checks    a List of checks
     * @param message   the message to be checked
     * @param helpers   an istance of the helpers
     * @param isRequest set true if the request has to be checked, false for the response
     * @return returns the result of the checks (true if all the tests are successful)
     */
    public static boolean executeChecks(List<Check> checks,
                                        HTTPReqRes message,
                                        IExtensionHelpers helpers,
                                        boolean isRequest) throws ParsingException {
        for (Check c : checks) {
            String msg_str = "";
            IRequestInfo req_info = null;
            IResponseInfo res_info = null;
            if (isRequest) req_info = helpers.analyzeRequest(message.getRequest());
            if (!isRequest) res_info = helpers.analyzeResponse(message.getResponse());
            if (c.in == null) {
                throw new ParsingException("from tag in checks is null");
            }
            switch (c.in) {
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

            if (c.isParamCheck) {
                try {
                    Pattern p = c.in == Utils.MessageSection.URL ?
                            Pattern.compile("(?<=[?&]" + c.what + "=)[^\\n&]*") :
                            Pattern.compile("(?<=" + c.what + ":\\s?)[^\\n]*");
                    Matcher m = p.matcher(msg_str);

                    String val = "";
                    if (m.find()) {
                        val = m.group();
                    } else {
                        return false;
                    }

                    if (c.op == null && val.length() != 0) {
                        // if it passed all the splits without errors, the param is present, but no checks are specified
                        // so result is true
                        continue;
                    }

                    switch (c.op) {
                        case IS:
                            if (!c.op_val.equals(val)) {
                                return false;
                            }
                            break;
                        case IS_NOT:
                            if (!!c.op_val.equals(val)) {
                                return false;
                            }
                            break;
                        case CONTAINS:
                            if (!val.contains(c.op_val)) {
                                return false;
                            }
                            break;
                        case NOT_CONTAINS:
                            if (!!val.contains(c.op_val)) {
                                return false;
                            }
                            break;
                        case IS_PRESENT:
                            continue; // if it gets to this, the searched param is already found
                        case IS_NOT_PRESENT:
                            return false;
                    }
                } catch (ArrayIndexOutOfBoundsException e) {
                    //e.printStackTrace();
                    if (c.op != null) {
                        if (c.op != Utils.CheckOps.IS_NOT_PRESENT) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else {
                if (!msg_str.contains(c.what)) {
                    if (c.op != null) {
                        if (c.op != Utils.CheckOps.IS_NOT_PRESENT) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                } else {
                    if (c.op != null) {
                        if (c.op == Utils.CheckOps.IS_NOT_PRESENT) return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * Function that gets all the parameters of an url
     * (<a href="https://stackoverflow.com/questions/11733500/getting-url-parameter-in-java-and-extract-a-specific-text-from-that-url">stackoverflow</a>)
     *
     * @param url the url from which extract the parameters
     * @return all the parameters
     */
    public static Map<String, String> getUrlParams(URL url) {
        String query = url.getQuery();
        String[] params = query.split("&");
        Map<String, String> map = new HashMap<String, String>();

        for (String param : params) {
            String name = param.split("=")[0];
            String value = param.split("=")[1];
            map.put(name, value);
        }
        return map;
    }
}
