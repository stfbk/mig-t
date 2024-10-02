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

import java.util.ArrayList;
import java.util.List;

/** This class provides an API for an Operation module, to be used by other modules. */
public class Operation_API extends API {
    public HTTPReqRes message;
    public List<Var> vars;
    boolean is_request;

    public Operation_API(HTTPReqRes message, boolean is_request) {
        this.message = message;
        this.is_request = is_request;
        this.vars = new ArrayList<>();
    }

    public Operation_API(List<Var> vars) {
        this.vars = vars;
    }
}
