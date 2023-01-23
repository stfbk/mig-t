package burp;

/**
 * Class which is intended to substitute the <code>IHTTPRequestResponse</code> one, because of serialization support
 *
 * @author Matteo Bitussi
 */
public class HTTPReqRes implements Cloneable {
    static public int instances;
    private String request_url;
    private byte[] request;
    private byte[] response;
    private String host;
    private int port;
    private String protocol;

    /**
     * Instantiate an HTTPReqRes element
     *
     * @param request  the request in byte[] form
     * @param response the response in byte[] form
     */
    public HTTPReqRes(byte[] request, byte[] response) {
        this.setRequest(request);
        this.setResponse(response);
        instances++;
    }

    /**
     * Istantiate an HTTPReqRes element from a <code>IHttpRequestResponsePersisted</code> message
     *
     * @param message the message to be created from
     * @param helpers the helpers
     */
    public HTTPReqRes(IHttpRequestResponsePersisted message, IExtensionHelpers helpers) {
        this.setRequest(message.getRequest());
        this.setResponse(message.getResponse());
        this.setRequest_url(helpers.analyzeRequest(message).getUrl().toString());
        IHttpService service = message.getHttpService();
        this.setHost(service.getHost());
        this.setPort(service.getPort());
        this.setProtocol(service.getProtocol());
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
        this.setRequest(message.getRequest());
        if (!isRequest) this.setResponse(message.getResponse());
        this.setRequest_url(helpers.analyzeRequest(message).getUrl().toString());
        IHttpService service = message.getHttpService();
        this.setHost(service.getHost());
        this.setPort(service.getPort());
        this.setProtocol(service.getProtocol());
        instances++;
    }

    public byte[] getRequest() {
        return request;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    public byte[] getResponse() {
        return response;
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
