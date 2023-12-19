package migt;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.IHttpService;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class which is intended to substitute the <code>IHTTPRequestResponse</code> one, because of serialization support
 */
public class HTTPReqRes implements Cloneable {
    static public int instances;
    public Integer index = -1; // index of the message wrt the burp proxy
    public boolean isRequest = false;
    public boolean isResponse = false;
    public int body_offset_req; // identifies the index where the body ends in the request
    public int body_offset_resp; // the index where teh body of the response starts
    byte[] body_req = null; // the body of the request message
    byte[] body_resp = null; // the body of the response message
    // host data
    private String host;
    private int port = 0;
    private String protocol;
    // message data
    private String request_url; // The url of the request (not the header)
    private byte[] request;
    private byte[] response;
    private List<String> headers_req; // the headers of the request
    private List<String> headers_resp; // the headers of the response

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
    public HTTPReqRes(IHttpRequestResponse message, IExtensionHelpers helpers, boolean isRequest, int index) {
        if (!isRequest) {
            this.isResponse = true;
            this.setResponse(message.getResponse());
            this.headers_resp = helpers.analyzeResponse(message.getResponse()).getHeaders();
            this.body_offset_resp = helpers.analyzeRequest(message.getResponse()).getBodyOffset();
        }

        this.index = index;

        // the request is always present in a IHTTPRequestResponse
        this.isRequest = true;
        this.setRequest(message.getRequest());
        this.setRequest_url(helpers.analyzeRequest(message).getUrl().toString());
        this.headers_req = helpers.analyzeRequest(message.getRequest()).getHeaders();
        this.request_url = helpers.analyzeRequest(message).getUrl().toString();
        this.body_offset_req = helpers.analyzeRequest(message.getRequest()).getBodyOffset();

        // set host info
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

    /**
     * returns true if the message has the body
     *
     * @param isRequest select the request or the response message
     * @return true if it has body, false otherwise
     */
    public boolean hasBody(boolean isRequest) {
        if (isRequest && this.body_offset_req == 0) {
            return false;
        }
        return isRequest || this.body_offset_resp != 0;
    }

    public byte[] getBody(boolean isRequest) {
        if (isRequest && (!this.hasBody(isRequest) | this.request == null | this.request.length == 0)) {
            throw new RuntimeException("called getBody, but class is not properly initialized");
        }
        if (!isRequest && (!this.hasBody(isRequest) | this.response == null | this.response.length == 0)) {
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
    public byte[] getMessage(boolean isRequest) {
        if (isRequest && this.request == null) {
            throw new RuntimeException("Called getMessage on a message that is not initialized");
        } else if (!isRequest && this.response == null) {
            throw new RuntimeException("Called getMessage on a message that is not initialized");
        }
        build_message(isRequest);

        if (isRequest) {
            request = build_message(isRequest);
        } else {
            response = build_message(isRequest);
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

    public void setResponse(byte[] response) {
        this.response = response;
    }

    public String getUrl() {
        return this.request_url;
    }

    public String getRequest_url() {
        return request_url;
    }

    public void setRequest_url(String request_url) {
        if (this.request_url == null) {
            this.request_url = request_url;
        } else {
            this.request_url = request_url;
            updateHeadersWHurl();
        }
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

    /**
     * Get the given parameter value from the url of the request messsage
     *
     * @param param the parameter name to be searched
     * @return the value of the parameter
     */
    public String getUrlParam(String param) {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        List<NameValuePair> params = new ArrayList<>();

        try {
            params = URLEncodedUtils.parse(
                    new URI(request_url), StandardCharsets.UTF_8
            );
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        for (NameValuePair p : params) {
            if (p.getName().equals(param)) {
                return p.getValue();
            }
        }

        return "";
    }

    /**
     * Execute a regex over the complete url and return the value matched
     *
     * @param regex the regex to execute
     * @return the matched value
     */
    public String getUrlRegex(String regex) {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        String res = "";
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(request_url);
        if (m.find()) {
            res = m.group();
        }
        return res;
    }

    /**
     * Edit this message's URL with a regex, everything matched will be replaced by new_value
     *
     * @param regex     the regex to execute
     * @param new_value the value to substitute to matched content
     */
    public void editUrlRegex(String regex, String new_value) {
        String old_url = getUrl();
        Pattern p = Pattern.compile(regex);
        Matcher m = p.matcher(old_url);
        String new_url = m.replaceAll(new_value);
        setRequest_url(new_url);
    }

    /**
     * Edits the given parameter value with the new given value
     *
     * @param param the parameter name
     * @param value the new value of the parameter
     */
    public void editUrlParam(String param, String value) throws ParsingException {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        List<NameValuePair> params = new ArrayList<>();

        try {
            params = URLEncodedUtils.parse(
                    new URI(request_url), StandardCharsets.UTF_8
            );
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        int indx = -1;
        int c = 0;
        for (NameValuePair p : params) {
            if (p.getName().equals(param)) {
                indx = c;
            }
            c++;
        }

        if (indx == -1) {
            throw new ParsingException("Could not find parameter " + param + " in url");
        }

        params.set(indx, new BasicNameValuePair(param, value));

        String new_query = URLEncodedUtils.format(params, "utf-8");

        URL url = null;
        try {
            url = new URL(request_url);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        request_url = request_url.replaceAll(
                "\\Q" + java.util.regex.Matcher.quoteReplacement(url.getQuery()) + "\\E",
                new_query);

        updateHeadersWHurl();
    }

    /**
     * Removes the given param from the request url query parameters
     *
     * @param name param name
     */
    public void removeUrlParam(String name) throws ParsingException {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        List<NameValuePair> params = new ArrayList<>();

        try {
            params = URLEncodedUtils.parse(
                    new URI(request_url), StandardCharsets.UTF_8
            );
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        int indx = -1;
        int c = 0;
        for (NameValuePair p : params) {
            if (p.getName().equals(name)) {
                indx = c;
            }
            c++;
        }

        if (indx == -1) {
            throw new ParsingException("Could not find parameter " + name + " in url");
        }

        params.remove(indx);

        String new_query = URLEncodedUtils.format(params, "utf-8");

        URL url = null;
        try {
            url = new URL(request_url);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        request_url = request_url.replaceAll(
                "\\Q" + java.util.regex.Matcher.quoteReplacement(url.getQuery()) + "\\E",
                new_query);

        updateHeadersWHurl();
    }

    /**
     * Adds an url query parameter to the request url. If parameter already present, concatenate new value to old.
     *
     * @param name  the name of the new parameter
     * @param value the value of the new parameter
     */
    public void addUrlParam(String name, String value) {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        List<NameValuePair> params = new ArrayList<>();

        try {
            params = URLEncodedUtils.parse(
                    new URI(request_url), StandardCharsets.UTF_8
            );
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        int c = 0;
        boolean found = false;
        for (NameValuePair p : params) {
            if (p.getName().equals(name)) {
                found = true;
                break;
            }
            c += 1;
        }

        if (found) {
            String old_value = params.get(c).getValue();
            old_value += value;
            params.set(c, new BasicNameValuePair(name, old_value));
        } else {
            params.add(new BasicNameValuePair(name, value));
        }

        String new_query = URLEncodedUtils.format(params, "utf-8");

        URL url = null;
        try {
            url = new URL(request_url);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        request_url = request_url.replaceAll(
                "\\Q" + java.util.regex.Matcher.quoteReplacement(url.getQuery()) + "\\E",
                new_query);

        updateHeadersWHurl();
    }

    /**
     * Get the given parameter value from the head
     *
     * @param isRequest if the message is a request
     * @param param     the parameter name to be searched
     * @return the value of the parameter
     */
    public String getHeadParam(boolean isRequest, String param) {
        List<String> headers = isRequest ? this.headers_req : this.headers_resp;

        for (String s : headers) {
            if (s.contains(param)) {
                String value = s.substring(s.indexOf(":") + 1);
                return value.strip();
            }
        }
        return "";
    }

    /**
     * Execute a regex over the headers and return the first value matched
     *
     * @param regex the regex to execute
     * @return the matched value
     */
    public String getHeadRegex(boolean isRequest, String regex) {
        List<String> headers = isRequest ? this.headers_req : this.headers_resp;

        String res = "";
        Pattern p = Pattern.compile(regex);
        for (String s : headers) {
            Matcher m = p.matcher(s);
            if (m.find()) {
                res = m.group();
            }
        }
        return res;
    }


    /**
     * Edits the Header of the given message
     *
     * @param isRequest select the request or teh response
     * @param param     the name of the header
     * @param new_value the new value
     */
    public void editHeadParam(boolean isRequest, String param, String new_value) {
        List<String> headers = isRequest ? this.headers_req : this.headers_resp;

        int indx = -1;

        for (String s : headers) {
            if (s.contains(param)) {
                indx = headers.indexOf(s);
                break;
            }
        }

        if (isRequest) {
            headers_req.set(indx, param + ": " + new_value);
        } else {
            headers_resp.set(indx, param + ": " + new_value);
        }
    }

    /**
     * Edit the header of the message with a regex
     *
     * @param isRequest select the request or response message
     * @param regex     the regex to execute
     * @param new_value the new value to substitute
     */
    public void editHeadRegex(boolean isRequest, String regex, String new_value) {
        if (!isRequest && !this.isResponse) {
            throw new RuntimeException("tried to edit headers of response not yet received");
        }

        getHeaders(isRequest).replaceAll(header -> {
            Pattern p = Pattern.compile(regex);
            Matcher m = p.matcher(header);
            header = m.replaceAll(new_value);
            return header;
        });
    }

    /**
     * Adds a Header to the given message
     *
     * @param isRequest if the message to edit is the request or the response
     * @param name      the name of the new header
     * @param value     the value of the new header
     */
    public void addHeadParameter(boolean isRequest, String name, String value) {
        List<String> headers = isRequest ? this.headers_req : this.headers_resp;

        int c = 0;
        boolean found = false;

        for (String h : headers) {
            if (h.startsWith(name + ":")) {
                found = true;
                break;
            }
            c += 1;
        }

        if (found) {
            String old_header = headers.get(c);
            old_header += value;
            headers_req.set(c, old_header);
        } else {
            headers.add(name + ": " + value);
        }
    }

    /**
     * Removes the header from the given message
     *
     * @param isRequest select the request or the response
     * @param name      the name of the header
     */
    public void removeHeadParameter(boolean isRequest, String name) {
        List<String> headers = isRequest ? this.headers_req : this.headers_resp;

        for (String h : headers) {
            if (h.contains(name)) {
                headers.remove(h);
                break;
            }
        }

        if (isRequest) {
            this.headers_req = headers;
        } else {
            this.headers_resp = headers;
        }
    }

    /**
     * Given a message, get the given parameter value from the body, note that it accepts a regular expression, and
     * everything matched will be returned as a value
     *
     * @param isRequest if the message is a request
     * @param regex     the parameter to be searched as a regex, everything matched by this will be returned as a value
     * @return the value of the parameter
     */
    public String getBodyRegex(boolean isRequest, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(new String(getBody(isRequest), StandardCharsets.UTF_8));

        String res = "";
        while (matcher.find()) {
            res = matcher.group();
            break;
        }
        return res;
    }

    /**
     * Edit the body of the message. Replaces the matched content of the regex with the new value.
     *
     * @param isRequest select the request or response message
     * @param regex     the regex to execute
     * @param new_value the new value to substitute
     */
    public void editBodyRegex(boolean isRequest, String regex, String new_value) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(new String(getBody(isRequest), StandardCharsets.UTF_8));

        String new_body = matcher.replaceFirst(new_value);
        setBody(isRequest, new_body);
    }

    /**
     * Append to the body of the message the given value. If the message doesn't have a body it creates it.
     *
     * @param isRequest select the request or response message
     * @param new_value the value to append
     */
    public void addBody(boolean isRequest, String new_value) {
        if (hasBody(isRequest)) {
            String body = new String(getBody(isRequest));
            body += new_value;
            setBody(isRequest, body);
        } else {
            if (isRequest) {
                body_offset_req = 1; // this is for recognizing body in hasBody method
                body_req = new_value.getBytes(StandardCharsets.UTF_8);
            } else {
                body_offset_resp = 1; // this is for recognizing body in hasBody method
                body_resp = new_value.getBytes(StandardCharsets.UTF_8);
            }
        }
    }

    /**
     * Updates the headers in this request message with the acctual url value
     */
    public void updateHeadersWHurl() throws RuntimeException {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        URL url = null;
        try {
            url = new URL(request_url);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        if (headers_req.isEmpty()) {
            throw new RuntimeException("Message headers not properly initialized");
        }

        String[] header_0 = headers_req.get(0).split(" ");

        String new_header_0 = header_0[0] + " " + url.getPath();
        if (url.getQuery() != null) {
            new_header_0 += "?" + url.getQuery();
        }

        //if (url.getRef() != null) {
        //    new_header_0 += "#" + url.getRef();
        //}

        new_header_0 += " " + url.getProtocol().toUpperCase();
        new_header_0 += "/" + header_0[2].split("/")[1];

        String new_header_1 = "Host: " + url.getHost();

        if (!headers_req.get(1).contains("Host")) {
            throw new RuntimeException("could not find Host header in header");
        }

        headers_req.set(0, new_header_0);
        headers_req.set(1, new_header_1);
    }

    /**
     * Function to check if the given message matches a message_type
     *
     * @param msg_type the message type to check against it
     * @return true or false, if matched or not respectively
     */
    public boolean matches_msg_type(MessageType msg_type) {
        boolean matchedMessage = false;
        try {
            /* If the response message name is searched, the getByResponse will be true.
             * so messageIndex have to search for the request, and then evaluate the response
             */
            if (msg_type.getByResponse) {
                if (!isResponse) return false; // both request and response have to be present
                matchedMessage = Tools.executeChecks(
                        msg_type.checks,
                        this,
                        true,
                        new ArrayList<>() // TODO: fix
                );
            } else if (msg_type.getByRequest) {
                if (!isResponse) return false; // both request and response have to be present
                matchedMessage = Tools.executeChecks(
                        msg_type.checks,
                        this,
                        false,
                        new ArrayList<>() // TODO: fix
                );
            } else {
                if (!msg_type.isRequest && !isResponse) return false; // this message is not containing a response
                matchedMessage = Tools.executeChecks(
                        msg_type.checks,
                        this,
                        msg_type.isRequest,
                        new ArrayList<>() // TODO: fix
                );
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return matchedMessage;
    }

    /**
     * Returns a string representation of all the headers of the message
     *
     * @param isRequest select the request or the response
     * @return
     */
    public String getHeadersString(boolean isRequest) {
        List<String> headers_string = getHeaders(isRequest);
        return String.join("\r\n", headers_string);
    }

    /**
     * An enum representing the possible message sections
     */
    public enum MessageSection {
        HEAD,
        BODY,
        URL,
        RAW;

        /**
         * Function that given a message section in form of String, returns the corresponding MessageSection enum value
         *
         * @param input the input string
         * @return the MessageSection enum value
         * @throws ParsingException if the input does not correspond to any of the possible messagesections
         */
        public static MessageSection fromString(String input) throws ParsingException {
            if (input != null) {
                switch (input) {
                    case "head":
                        return HEAD;
                    case "body":
                        return BODY;
                    case "url":
                        return URL;
                    case "raw":
                        return RAW;
                    default:
                        throw new ParsingException("message section not valid");
                }
            } else {
                throw new NullPointerException();
            }
        }
    }
}
