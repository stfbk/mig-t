/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.migt;

import java.awt.BorderLayout;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Objects;
import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

/** Main class executed by ZAP */
public class ZAPextender extends ExtensionAdaptor implements ProxyListener {

    public static PrintStream printStream;
    public static PrintStream errorStream;
    private GUIclass mainPane; // The GUI
    private AbstractPanel statusPanel = null; // wrap per OWASP ZAP

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
            SwingUtilities.invokeLater(
                    () -> {
                        statusPanel = new AbstractPanel();
                        statusPanel.setLayout(new BorderLayout());
                        statusPanel.setName("MIG-T");
                        statusPanel.setIcon(
                                new ImageIcon(getClass().getResource("resources/logo.png")));

                        //                        //setup output stream in Burp
                        //                        OutputStream stdOut = callbacks.getStdout();
                        //                        OutputStream stdErr = callbacks.getStderr();
                        //                        printStream = new PrintStream(stdOut);
                        //                        errorStream = new PrintStream(stdErr);

                        //this should allow you to test the operation but could
                        //Imply redirection
                        //of all ZAP stderr and stdout to our panel

                        //                OutputStream stdOut = System.out;
                        //                OutputStream stdErr = System.err;
                        //                printStream = new PrintStream(stdOut);
                        //                errorStream = new PrintStream(stdErr);

                        // TODO: check this code, before it created a separate instance
                        mainPane = new GUIclass();

                        _mainPane_.messageViewer = new ReqResPanel();
                        _mainPane_.splitPane.setRightComponent(mainPane.messageViewer);

                        /*             I should have replaced these elements in the hook method
                                       callbacks.registerProxyListener(BurpExtender.this);
                                       callbacks.registerHttpListener(BurpExtender.this);
                        */
                        statusPanel.add(_mainPane_);
                    });
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

        HTTPReqRes message =
                new HTTPReqRes(
                        // messageInfo,
                        msg,
                        messageIsRequest,
                        // proxy_message.getMessageReference()
                        msg.getHistoryRef().getHistoryId());

        if (mainPane.INTERCEPT_ENABLED) {

            //
            //
            //            /* Check at which port of the proxy the message has been received
            //               if it is different from the one of the session avoid message*/
            //            if (!port.equals(mainPane.actual_operation.session_port)) {
            //                return;
            //            }

            // Log the received message by adding it to the list of received messages
            log_message(messageIsRequest, msg);

            MessageType msg_type = null;
            try {
                msg_type =
                        MessageType.getFromList(
                                mainPane.messageTypes, mainPane.actual_operation.getMessageType());
            } catch (Exception e) {
                e.printStackTrace();
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

        /* This is the original code for the saveBuffer
                       if (mainPane.recording) {
                           if (!messageIsRequest) { // do not remove
                               synchronized (mainPane.interceptedMessages) {
                                   IHttpRequestResponsePersisted actual =
        callbacks.saveBuffersToTempFiles(messageInfo);
                                   mainPane.interceptedMessages.add(
                                           new HTTPReqRes(actual)
                                   );
                                   if (mainPane.defaultSession != null) {
                                       mainPane.defaultSession.addMessage(actual,
        mainPane.FILTERING);
                                   }
                               }
                           }
                       }
               */
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

            MessageType msg_type = null;
            try {
                msg_type =
                        MessageType.getFromList(
                                mainPane.messageTypes, mainPane.actual_operation.getMessageType());
            } catch (Exception e) {
                e.printStackTrace();
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
