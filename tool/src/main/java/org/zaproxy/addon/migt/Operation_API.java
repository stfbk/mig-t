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
