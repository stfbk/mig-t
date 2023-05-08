package burp;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Class which is intended to substitute the <code>IHTTPRequestResponse</code> one, because of serialization support
 *
 * @author Matteo Bitussi
 */
public class HTTPReqRes implements Cloneable {
    static public int instances;

    // host data
    private String host;
    private int port = 0;
    private String protocol;

    // message data
    private String request_url;
    private byte[] request;
    private byte[] response;

    public boolean isRequest = false;
    public boolean isResponse = false;
    public int body_offset_req; // identifies the index where the body ends in the request
    public int body_offset_resp; // the index where teh body of the response starts
    private List<String> headers_req; // the headers of the request
    private List<String> headers_resp; // the headers of the response
    byte[] body_req; // the body of the request message
    byte[] body_resp; // the body of the response message


    /**
     * Instantiate an HTTPReqRes element
     *
     * @param request  the request in byte[] form
     * @param response the response in byte[] form
     */
    public HTTPReqRes(byte[] request, byte[] response) {
        this.isRequest = true;
        this.isResponse = true;
        this.setRequest(request);
        this.setResponse(response);
        instances++;
    }

    /**
     * Instantiate an HTTPReqRes element from a <code>IHttpRequestResponsePersisted</code> message
     *
     * @param message the message to be created from
     * @param helpers the helpers
     */
    public HTTPReqRes(IHttpRequestResponsePersisted message, IExtensionHelpers helpers) {
        this.isRequest = true;
        this.isResponse = true;
        this.setRequest(message.getRequest());
        this.setResponse(message.getResponse());
        this.setRequest_url(helpers.analyzeRequest(message).getUrl().toString());
        IHttpService service = message.getHttpService();
        this.setHost(service.getHost());
        this.setPort(service.getPort());
        this.setProtocol(service.getProtocol());
        this.body_offset_req = helpers.analyzeRequest(message.getRequest()).getBodyOffset();
        this.body_offset_resp = helpers.analyzeResponse(message.getResponse()).getBodyOffset();
        this.headers_req = helpers.analyzeRequest(message.getRequest()).getHeaders();
        this.headers_resp = helpers.analyzeResponse(message.getResponse()).getHeaders();

        instances++;
    }

    /**
     * Instantiate an HTTPReqRes element. If a message is a request it does not gather the response
     *
     * @param message   an IHTTPRequestResponse message
     * @param helpers   an istance of the IExtensionHelpers
     * @param isRequest true if the message is a request, false otherwise
     */
    public HTTPReqRes(IHttpRequestResponse message, IExtensionHelpers helpers, Boolean isRequest) {
        this.isRequest = isRequest;
        this.isResponse = !isRequest;
        // TODO: in theory, if a IHttpRequestResponse object contains a response, it should contain also the request

        if (isRequest) {
            this.setRequest(message.getRequest());
            this.setRequest_url(helpers.analyzeRequest(message).getUrl().toString());
            helpers.analyzeRequest(message.getRequest()).getBodyOffset();
            this.headers_req = helpers.analyzeRequest(message.getRequest()).getHeaders();
            this.request_url = helpers.analyzeRequest(message).getUrl().toString();
        } else {
            this.setResponse(message.getResponse());
            helpers.analyzeResponse(message.getResponse()).getBodyOffset();
            this.headers_resp = helpers.analyzeResponse(message.getResponse()).getHeaders();
        }

        IHttpService service = message.getHttpService();
        this.setHost(service.getHost());
        this.setPort(service.getPort());
        this.setProtocol(service.getProtocol());

        instances++;
    }

    /**
     * Function used to replace an IHttpRequestResponse message with the values contained in this object
     *
     * @param message the message to be replaced
     * @param helpers the burp helpers
     * @return the edited message with the request and/or response replaced
     */
    public IHttpRequestResponse replaceBurpMessage(IHttpRequestResponse message, IExtensionHelpers helpers) {
        // TODO: eventually rebuild the message with the edited parts, here or when edited ?
        if (isRequest) {
            message.setRequest(request);
        }
        if (isResponse) {
            message.setResponse(response);
        }
        if (host != null && port != 0 && protocol != null) {
            message.setHttpService(
                    this.getHttpService(helpers)
            );
        }
        return message;
    }

    public IHttpService getHttpService(IExtensionHelpers helpers) {
        return helpers.buildHttpService(
                host,
                port,
                protocol
        );
    }

    public String getUrlHeader() {
        if (!isRequest)
            throw new RuntimeException("called getUrlHeader on a response message");

        return this.headers_req.get(0);
    }

    public void setUrlHeader(String url_header) {
        if (!isRequest)
            throw new RuntimeException("called setUrlHeader on a response message");

        this.headers_req.set(0, url_header);
    }

    public byte[] getBody(boolean isRequest) {
        if (isRequest && (this.body_offset_req == 0 | this.request == null | this.request.length == 0)) {
            throw new RuntimeException("called getBody, but class is not properly initialized");
        }
        if (!isRequest && (this.body_offset_resp == 0 | this.response == null | this.response.length == 0)) {
            throw new RuntimeException("called getBody, but class is not properly initialized");
        }

        if (isRequest) {
            // if asking for the first time, take the body from the message
            if (this.body_req == null)
                this.body_req = Arrays.copyOfRange(this.request, this.body_offset_req, this.request.length);
            return this.body_req;
        } else {
            if (this.body_resp == null)
                this.body_resp = Arrays.copyOfRange(this.response, this.body_offset_resp, this.response.length);
            return this.body_resp;
        }
    }

    public List<String> getHeaders(boolean isRequest) {
        return isRequest ? this.headers_req : this.headers_resp;
    }

    /**
     * Used to build the message based on the changes made
     */
    private byte[] build_message(IExtensionHelpers helpers, boolean isRequest) {
        // TODO: this could be written avoiding helpers class
        if (isRequest) {
            this.request = helpers.buildHttpMessage(headers_req, getBody(true));
            return this.request;
        } else {
            this.response = helpers.buildHttpMessage(headers_resp, getBody(false));
            return this.response;
        }
    }

    /**
     * Builds the message taking the headers and the body, without using the burp's helpers.
     *
     * @param isRequest true if message is a request message
     * @return
     */
    public byte[] build_message(boolean isRequest) {
        String builded = "";
        byte[] body = getBody(isRequest);

        List<String> headers = getHeaders(isRequest);
        String content_header = "Content-Length: " + body.length;

        for (String header : headers) {
            if (header.contains("Content-Length:")) {
                if (body.length == 0)
                    continue;// if Content-Length header found, but message has no body, remove.
                builded += content_header;

            } else {
                builded += header;
            }
            builded += "\r\n";
        }
        builded += "\r\n"; // last row of header before body

        if (body.length != 0)
            builded += new String(body);

        return builded.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Get the message in bytes with the changes made
     *
     * @param isRequest to specify the request or the response
     * @return the message
     */
    public byte[] getMessage(boolean isRequest, IExtensionHelpers helpers) {
        if (isRequest && this.request == null) {
            throw new RuntimeException("Called getMessage on a message that is not initialized");
        } else if (!isRequest && this.response == null) {
            throw new RuntimeException("Called getMessage on a message that is not initialized");
        }
        build_message(helpers, isRequest);

        return isRequest ? request : response;
    }

    /**
     * Get the message without updating it with the changes
     *
     * @param isRequest
     * @return
     */
    public byte[] getMessage(boolean isRequest) {
        // TODO: this is probably a source of bugs, called without noticing that it doesnt get the updated message
        if (isRequest && this.request == null) {
            throw new RuntimeException("Called getMessage on a message that is not initialized");
        } else if (!isRequest && this.response == null) {
            throw new RuntimeException("Called getMessage on a message that is not initialized");
        }

        return isRequest ? request : response;
    }

    public void setHeaders(boolean isRequest, List<String> headers) {
        if (isRequest) {
            this.headers_req = headers;
        } else {
            this.headers_resp = headers;
        }
    }

    /**
     * Set the body of the request or response message with a new value
     *
     * @param isRequest
     * @param body
     */
    public void setBody(boolean isRequest, byte[] body) {
        if (isRequest) {
            this.body_req = body;
        } else {
            this.body_resp = body;
        }
    }

    /**
     * Set the body of the request or response message with a new value
     *
     * @param isRequest
     * @param body
     */
    public void setBody(boolean isRequest, String body) {
        setBody(isRequest, body.getBytes());
    }

    /**
     * Get the original un-edited request message
     *
     * @return
     */
    public byte[] getRequest() {
        return request;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    /**
     * Get the original un-edited response message
     *
     * @return
     */
    public byte[] getResponse() {
        return response;
    }

    public String getUrl() {
        return this.request_url;
    }

    public void setResponse(byte[] response) {
        this.response = response;
    }

    public String getRequest_url() {
        return request_url;
    }

    public void setRequest_url(String request_url) {
        this.request_url = request_url;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        return super.clone();
    }
}
