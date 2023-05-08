package burp;

/**
 * This class provides an API for an Operation module, to be used by other modules.
 */
public class Operation_API extends API {
    public HTTPReqRes message;
    boolean is_request;

    public Operation_API(HTTPReqRes message, boolean is_request) {
        this.message = message;
        this.is_request = is_request;
    }
}
