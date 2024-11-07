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

            //                        //setup output stream in Burp
            //                        OutputStream stdOut = callbacks.getStdout();
            //                        OutputStream stdErr = callbacks.getStderr();
            //                        printStream = new PrintStream(stdOut);
            //                        errorStream = new PrintStream(stdErr);

            // this should allow you to test the operation but could
            // Imply redirection
            // of all ZAP stderr and stdout to our panel

            // TODO: understand if this needs to exist or is useless
            OutputStream stdOut = System.out;
            OutputStream stdErr = System.err;
            printStream = new PrintStream(stdOut);
            errorStream = new PrintStream(stdErr);

            // TODO: this should not be needed, it's a duplicate
            // mainPane = new GUIclass();

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

    // This is the starting Burp code, replaced by the hook function

    //    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    //        System.out.println("Initializing extension");
    //
    //        this.callbacks = callbacks;
    //        helpers = callbacks.getHelpers();
    //
    //        callbacks.setExtensionName("MIG Testing tool");
    //
    //        //The UI is created
    //        SwingUtilities.invokeLater(() -> {
    //            // setup output stream
    //            OutputStream stdOut = callbacks.getStdout();
    //            OutputStream stdErr = callbacks.getStderr();
    //
    //            printStream = new PrintStream(stdOut);
    //            errorStream = new PrintStream(stdErr);
    //
    //            mainPane = new Main();
    //            mainPane.callbacks = callbacks;
    //            mainPane.messageViewer = callbacks.createMessageEditor(mainPane.controller,
    // false);
    //            mainPane.splitPane.setRightComponent(mainPane.messageViewer.getComponent());
    //
    //
    //            // add the custom tab to Burp's UI
    //            callbacks.addSuiteTab(/*BurpExtender.*/this);
    //
    //            // register ourselves as an HTTP listener
    //            callbacks.registerProxyListener(/*BurpExtender.*/this);
    //            //callbacks.registerHttpListener(BurpExtender.this);
    //        });
    //
    //
    //    }

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

        boolean messageIsRequest;
        if (msg.getRequestHeader().isEmpty()) {
            messageIsRequest = false;
        } else {
            messageIsRequest = true;
        }

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

        getView()
                .getOutputPanel()
                .append(
                        "\n\n ////////////////////////////////////////////////////////// \n\n Processing message header --> "
                                + msg.getRequestHeader()
                                + "\n\n --------------------------------------------------------------- \n\n Single headers \n");

        if (message.isRequest) {
            getView()
                    .getOutputPanel()
                    .append(msg.getRequestHeader().getPrimeHeader() + "\n\n-------------------------------------\n");

            for (HttpHeaderField s : msg.getRequestHeader().getHeaders()) {
                getView()
                        .getOutputPanel()
                        .append(s.toString() + "\n\n-------------------------------------\n");
            }
        } else if (message.isResponse) {
            getView()
                    .getOutputPanel()
                    .append(msg.getResponseHeader().getPrimeHeader() + "\n\n-------------------------------------\n");

            for (HttpHeaderField s : msg.getResponseHeader().getHeaders()) {
                getView()
                        .getOutputPanel()
                        .append(s.toString() + "\n\n-------------------------------------\n");
            }
        }

        System.out.println("mainPane.INTERCEPT_ENABLED = " + mainPane.INTERCEPT_ENABLED);

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
                e.printStackTrace();
                System.out.println("Error position is ZAPextender 0");
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
                        e.printStackTrace();
                        System.out.println("Error position is ZAPextender 1");
                        mainPane.actual_operation.applicable = false;
                    }
                }
            }
        }
        if (mainPane.recording) {
            if (!messageIsRequest) { // do not remove
                synchronized (mainPane.interceptedMessages) {
                    try {
                        HistoryReference historyRef =
                                new HistoryReference(
                                        Model.getSingleton().getSession(),
                                        HistoryReference.TYPE_TEMPORARY,
                                        msg);
                        mainPane.interceptedMessages.add(new HTTPReqRes(historyRef));

                        if (mainPane.defaultSession != null) {
                            mainPane.defaultSession.addMessage(historyRef, mainPane.FILTERING);
                        }

                    } catch (HttpMalformedHeaderException e) {
                        throw new RuntimeException(e);
                    } catch (DatabaseException e) {
                        throw new RuntimeException(e);
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    } catch (URISyntaxException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {

        boolean messageIsRequest;
        if (msg.getRequestHeader().isEmpty()) {
            messageIsRequest = false;
        } else {
            messageIsRequest = true;
        }

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
                e.printStackTrace();
                System.out.println("Error position is ZAPextender 2");
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
                        e.printStackTrace();
                        System.out.println("Error position is ZAPextender 3");
                        mainPane.actual_operation.applicable = false;
                    }
                }
            }
        }
        if (mainPane.recording) {
            if (!messageIsRequest) { // do not remove
                synchronized (mainPane.interceptedMessages) {
                    try {
                        HistoryReference historyRef =
                                new HistoryReference(
                                        Model.getSingleton().getSession(),
                                        HistoryReference.TYPE_TEMPORARY,
                                        msg);
                        mainPane.interceptedMessages.add(new HTTPReqRes(historyRef));

                        if (mainPane.defaultSession != null) {
                            mainPane.defaultSession.addMessage(historyRef, mainPane.FILTERING);
                        }

                    } catch (HttpMalformedHeaderException e) {
                        throw new RuntimeException(e);
                    } catch (DatabaseException e) {
                        throw new RuntimeException(e);
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    } catch (URISyntaxException e) {
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
