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

/** Listener class for ExecuteActive class */
public interface ExecuteActiveListener {

    /** Called when the execution of an ExecuteActivez is started */
    void onExecuteStart();

    /** Called when the execution of an ExecuteActive is finished */
    void onExecuteDone();

    /**
     * Called during the execution of an ExecuteActive, when a new operation is found and has to be
     * executed
     *
     * @param op the operation which has to be executed
     */
    void onNewProcessOperation(Operation op);

    /**
     * Called when the execution of an operation is completed
     *
     * @return the finished operation
     */
    Operation onOperationDone();

    /**
     * During an ExecuteActive execution, if a new session is found, this function is called, with
     * the session as an argument. You can return the session initiating it
     *
     * @param s the session
     * @return the initiated session
     */
    Session onNewSession(Session s);

    /**
     * This method is called during an ExecuteActive execution, when a new test is being executed
     *
     * @param actual_test The test that was being executed
     */
    void onNewTest(Test actual_test);

    /**
     * This method is called during an ExecuteActive execution, when a test has finished
     *
     * @param actual_test The test that was being executed
     */
    void onTestDone(Test actual_test);

    /**
     * This method is called whether an error occurs during the execution of the active tests
     *
     * @param actual_test The test that was being executed
     */
    void onError(Test actual_test);
}
