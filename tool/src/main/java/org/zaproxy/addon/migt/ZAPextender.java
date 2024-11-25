package org.zaproxy.addon.migt;

import java.awt.BorderLayout;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Objects;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Main class executed by ZAP */
public class ZAPextender extends ExtensionAdaptor implements ProxyListener {

    public static PrintStream printStream;
    public static PrintStream errorStream;
    private GUIclass mainPane; // The GUI
    private AbstractPanel statusPanel; // wrap per OWASP ZAP

    public static final String NAME = "MIGT";
    protected static final String PREFIX = "migt";

    private static final Logger LOGGER = LogManager.getLogger(ZAPextender.class);

    public ZAPextender() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    /** Main function creating the extension */
    @Override
    public void hook(ExtensionHook extensionHook) {
        System.out.println("Initializing extension");
        super.hook(extensionHook);

        extensionHook.addProxyListener(this);
        mainPane = new GUIclass();

        // As long as we're not running as a daemon
        if (hasView()) {
            extensionHook.getHookView().addStatusPanel(getStatusPanel(mainPane));
        }
    }

    private AbstractPanel getStatusPanel(GUIclass _mainPane_) {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new BorderLayout());
            statusPanel.setName("MIG-T");
            statusPanel.setIcon(new ImageIcon(getClass().getResource("/resources/logofbk1.png")));

            // this should allow you to test the operation but could
            // Imply redirection
            // of all ZAP stderr and stdout to our panel

            // TODO: understand if this needs to exist or is useless
            OutputStream stdOut = System.out;
            OutputStream stdErr = System.err;
            printStream = new PrintStream(stdOut);
            errorStream = new PrintStream(stdErr);


            _mainPane_.messageViewer = new ReqResPanel();
            _mainPane_.splitPane.setRightComponent(mainPane.messageViewer);

            /*             I should have replaced these elements in the hook method
                           callbacks.registerProxyListener(BurpExtender.this);
                           callbacks.registerHttpListener(BurpExtender.this);
            */
            statusPanel.add(_mainPane_);
        }
        return statusPanel;
    }


    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();
    }

    @Override
    public String getDescription() {
        return "This add-on provides custom security checks for web applications";
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {

        boolean messageIsRequest = true;

//        getView().getOutputPanel().append("\nInside RequestSent \n msg.getRequestHeader = " + msg.getRequestHeader() +
//                "\nmsg.getResponseHeader = " + msg.getResponseHeader());

        try {
            HistoryReference historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_TEMPORARY,
                            msg);
            msg.setHistoryRef(historyRef);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            System.err.println(e.getMessage());
            throw new RuntimeException(e);
        }

        HTTPReqRes message =
                new HTTPReqRes(
                        // messageInfo,
                        msg,
                        messageIsRequest,
                        // proxy_message.getMessageReference()
                        msg.getHistoryRef().getHistoryId());


        if (mainPane.INTERCEPT_ENABLED) {
            //            /* Check at which port of the proxy the message has been received
            //               if it is different from the one of the session avoid message*/
            //            if (!port.equals(mainPane.actual_operation.session_port)) {
            //                return;
            //            }

            // Log the received message by adding it to the list of received messages
            log_message(messageIsRequest, msg);
            System.out.println("Logged a message");

            MessageType msg_type = null;
            try {
                msg_type =
                        MessageType.getFromList(
                                mainPane.messageTypes, mainPane.actual_operation.getMessageType());
            } catch (Exception e) {
                System.err.println("error ZapExtender 1: \n" + e.getMessage());
                mainPane.actual_operation.applicable = false;
            }

            System.out.println("Here it's going to try matched_msg_type");

            // Check that the given message matches the message type specified in the test
            boolean matchMessage = message.matches_msg_type(msg_type, messageIsRequest);

            System.out.println("matched_msg_type = " + matchMessage);

            if (matchMessage) {
                // If the operation's action is an intercept
                if (Objects.requireNonNull(mainPane.actual_operation.getAction())
                        == Operation.Action.INTERCEPT) {
                    try {
                        processMatchedMsg(msg_type, message);
                        if (mainPane.actual_operation.then != null
                                & mainPane.actual_operation.then == Operation.Then.DROP) {
                            return false; // IN ZAP A BOOL IS RETURNED STATING IF THE MESSAGE HAVE
                            // TO BE SENT
                        }
                    } catch (Exception e) {
                        System.err.println("error ZapExtender 2: \n" + e.getMessage());
                        mainPane.actual_operation.applicable = false;
                    }
                }
            }
        }


        //questo pezzo in teoria non viene mai eseguito visto che messageIsRequest è true
        if (mainPane.recording) {
            if (!messageIsRequest) { // do not remove
                synchronized (mainPane.interceptedMessages) {

                    try {

                        mainPane.interceptedMessages.add(new HTTPReqRes(msg, messageIsRequest, msg.getHistoryRef().getHistoryId()));
//                        getView().getOutputPanel().append(
//                                "The intercepted messages list is long = " + mainPane.interceptedMessages.size() + "and contains:\n\n" +
//                                        mainPane.interceptedMessages.get(mainPane.interceptedMessages.size()-1).getUrl() + "\n\n" +
//                                        mainPane.interceptedMessages.get(mainPane.interceptedMessages.size()-1).Res_header + "\n\n" +
//                                        mainPane.interceptedMessages.get(mainPane.interceptedMessages.size()-1).Req_header + "\n\n -------------------------------------- \n");
//                        System.out.println("interceptedMessages size after add = " + mainPane.interceptedMessages.size());
                        if (mainPane.defaultSession != null) {
                            mainPane.defaultSession.addMessage(msg, mainPane.FILTERING);
                        }
                    } catch (MalformedURLException | DatabaseException | URISyntaxException |
                             HttpMalformedHeaderException e) {
                        System.err.println("error ZapExtender 5: \n" + e.getMessage());
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {

        boolean messageIsRequest = false;


        getView().getOutputPanel().append("\nInside ResponseReceive \n msg.getRequestHeader = " + msg.getRequestHeader() +
                "\nmsg.getResponseHeader = " + msg.getResponseHeader());

        try {
            HistoryReference historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_TEMPORARY,
                            msg);
            msg.setHistoryRef(historyRef);
        } catch (HttpMalformedHeaderException e) {
            throw new RuntimeException(e);
        } catch (DatabaseException e) {
            throw new RuntimeException(e);
        }

        HTTPReqRes message =
                new HTTPReqRes(
                        // messageInfo,
                        msg,
                        messageIsRequest,
                        // proxy_message.getMessageReference()
                        msg.getHistoryRef().getHistoryId());

        if (mainPane.INTERCEPT_ENABLED) {
            // TODO       add port control to separate sessions, check if the
            //            If this is not working, return false should prevent forwarding
            //            For the time being we avoid in door control, so we can manage
            //            only one session
            //
            //
            //            /* Check at which port of the proxy the message has been received
            //               if it is different from the one of the session avoid message*/
            //            if (!port.equals(mainPane.actual_operation.session_port)) {
            //                return;
            //            }

            // Log the received message by adding it to the list of received messages
            log_message(messageIsRequest, msg);
            System.out.println("Logged a message");

            MessageType msg_type = null;
            try {
                msg_type =
                        MessageType.getFromList(
                                mainPane.messageTypes, mainPane.actual_operation.getMessageType());
            } catch (Exception e) {
                System.err.println("error ZapExtender 3: \n" + e.getMessage());
                mainPane.actual_operation.applicable = false;
            }

            // Check that the given message matches the message type specified in the test
            boolean matchMessage = message.matches_msg_type(msg_type, messageIsRequest);

            if (matchMessage) {
                // If the operation's action is an intercept
                if (Objects.requireNonNull(mainPane.actual_operation.getAction())
                        == Operation.Action.INTERCEPT) {
                    try {
                        processMatchedMsg(msg_type, /*messageInfo,*/ message);
                        if (mainPane.actual_operation.then != null
                                & mainPane.actual_operation.then == Operation.Then.DROP) {
                            return false; // IN ZAP A BOOL IS RETURNED STATING IF THE MESSAGE HAVE
                            // TO BE SENT
                        }
                    } catch (Exception e) {
                        System.err.println("error ZapExtender 4: \n" + e.getMessage());
                        mainPane.actual_operation.applicable = false;
                    }
                }
            }
        }


        if (mainPane.recording) {
            //questo check viene superato -- rimuovi questo commento
            if (!messageIsRequest) { // do not remove
                synchronized (mainPane.interceptedMessages) {

                    try {

                        mainPane.interceptedMessages.add(new HTTPReqRes(msg, messageIsRequest, msg.getHistoryRef().getHistoryId()));
                        getView().getOutputPanel().append(
                                "\n\n" + mainPane.interceptedMessages.get(mainPane.interceptedMessages.size() - 1).getHeadersString(false) +
                                        "\n\n");
//                        getView().getOutputPanel().append(
//                                "The intercepted messages list is long = " + mainPane.interceptedMessages.size() + "and contains:\n\n" +
//                                        mainPane.interceptedMessages.get(mainPane.interceptedMessages.size()-1).getUrl() + "\n\n" +
//                                        mainPane.interceptedMessages.get(mainPane.interceptedMessages.size()-1).Res_header + "\n\n" +
//                                        mainPane.interceptedMessages.get(mainPane.interceptedMessages.size()-1).Req_header + "\n\n -------------------------------------- \n");
//                        System.out.println("interceptedMessages size after add = " + mainPane.interceptedMessages.size());
                        if (mainPane.defaultSession != null) {
                            mainPane.defaultSession.addMessage(msg, mainPane.FILTERING);
                        }
                    } catch (MalformedURLException | DatabaseException | URISyntaxException |
                             HttpMalformedHeaderException e) {
                        System.err.println("error ZapExtender 5: \n" + e.getMessage());
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        return true;
    }

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    /**
     * @param msg_type the message type to be used // @param messageInfo the original intercepted
     *     messageInfo to being able to edit the message
     * @param messageInfo a custom parsed message to be used in operations
     */
    private void processMatchedMsg(MessageType msg_type, HTTPReqRes messageInfo) {
        // TODO fix messageInfo.setHighlight("red");

        mainPane.actual_operation.setAPI(
                new Operation_API(messageInfo, msg_type.msg_to_process_is_request));


        System.out.println("Just before execute in processMatchedMsg");


        mainPane.actual_operation.execute();

        // if message has been edited inside operation update the value
        try {
            if (mainPane.actual_operation.processed_message != null) {
                if (msg_type.msg_to_process_is_request) {
                    if (!Arrays.equals(
                            messageInfo.getRequest(),
                            mainPane.actual_operation.processed_message)) {
                        messageInfo.setRequest(mainPane.actual_operation.processed_message);
                    }
                } else {
                    if (!Arrays.equals(
                            messageInfo.getResponse(),
                            mainPane.actual_operation.processed_message)) {
                        messageInfo.setResponse(mainPane.actual_operation.processed_message);
                    }
                }
            }
        } catch (UnsupportedOperationException e) {
            // This is thrown when an already issued request is being substituted
            System.err.println("Warning, edited message that has already been sent");
        }
        resume();
    }

    /** Tells the lock on the Execute Actives process to resume the execution */
    private void resume() {
        // Resume the execution thread
        synchronized (mainPane.waiting) {
            mainPane.waiting.notify();
        }
    }

    private void log_message(boolean isRequest, HttpMessage message) {
        mainPane.actual_operation.log_messages.add(message);
    }
}
