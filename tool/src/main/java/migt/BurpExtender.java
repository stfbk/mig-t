package migt;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Objects;

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
        /*
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
        */

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

        HTTPReqRes message = new HTTPReqRes(messageInfo, helpers, messageIsRequest);

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

            boolean matchMessage = message.matches_msg_type(msg_type);

            if (matchMessage) {
                Operation.MatchedMessage m = new Operation.MatchedMessage(
                        message,
                        HTTPReqRes.instances,
                        msg_type.msg_to_process_is_request,
                        !msg_type.msg_to_process_is_request,
                        false);
                mainPane.act_active_op.matchedMessages.add(m);

                // If the operation's action is an intercept
                if (Objects.requireNonNull(mainPane.act_active_op.getAction()) == Operation.Action.INTERCEPT) {
                    try {
                        processMatchedMsg(msg_type, messageInfo);
                        if (mainPane.act_active_op.then != null &
                                mainPane.act_active_op.then == Operation.Then.DROP) {
                            proxy_message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
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
        HTTPReqRes message = new HTTPReqRes(messageInfo, helpers, msg_type.msg_to_process_is_request);

        mainPane.act_active_op.helpers = helpers;
        mainPane.act_active_op.api.message = message;
        mainPane.act_active_op.api.is_request = msg_type.msg_to_process_is_request;
        mainPane.act_active_op.execute();

        // if message has been edited inside operation update the value
        try {
            if (mainPane.act_active_op.processed_message != null) {
                if (msg_type.isRequest) {
                    messageInfo.setRequest(mainPane.act_active_op.processed_message);
                } else {
                    messageInfo.setResponse(mainPane.act_active_op.processed_message);
                }
            }
        } catch (UnsupportedOperationException e) {
            // This is thrown when an already issued request is being substituted
            System.err.println("Warning, edited message that has already been sent");
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
