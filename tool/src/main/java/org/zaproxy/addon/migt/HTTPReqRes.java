package org.zaproxy.addon.migt;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.message.ParserCursor;
import org.apache.http.message.TokenParser;
import org.apache.http.util.Args;
import org.apache.http.util.CharArrayBuffer;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/**
 * Class which is intended to substitute the <code>IHTTPRequestResponse</code> one, because of
 * serialization support
 */
public class HTTPReqRes implements Cloneable {
    HttpMessage startingMessage;

    public static int instances;
    public Integer index = -1; // index of the message wrt the burp proxy
    public boolean isRequest = false;
    public boolean isResponse = false;
    public int body_offset_req; // identifies the index where the body ends in the request
    public int body_offset_resp; // the index where the body of the response starts
    byte[] body_req = null; // the body of the request message
    byte[] body_resp = null; // the body of the response message
    // host data
    private String host;
    private int port = -1;
    private String protocol;
    // message data
    private String request_url; // The url of the request (not the header)
    private byte[] request;
    private byte[] response;
    private List<String> headers_req; // the headers of the request
    private List<String> headers_resp; // the headers of the response

    public String Res_header;

    public String Res_body;

    public String Req_header;

    public String Req_body;

    /**
     * In OWASP ZAP there is no method that returns header + body at the same time this function
     * concatenates the two elements, if desired we could replace it with one that after passing an
     * HttpMessage the concatenation returns directly but I didn't want to alter too much the
     * starting code
     *
     * @param Fheader header del messaggio
     * @param Fbody body del messaggio
     */
    private byte[] concat_Request(byte[] Fheader, byte[] Fbody) {
        Req_header = new String(Fheader);
        Req_body = new String(Fbody);
        byte[] result = new byte[Fheader.length + Fbody.length];
        System.arraycopy(Fheader, 0, result, 0, Fheader.length);
        System.arraycopy(Fbody, 0, result, Fheader.length, Fbody.length);

        return result;
    }

    private byte[] concat_Response(byte[] Fheader, byte[] Fbody) {
        Res_header = new String(Fheader);
        Res_body = new String(Fbody);
        byte[] result = new byte[Fheader.length + Fbody.length];
        System.arraycopy(Fheader, 0, result, 0, Fheader.length);
        System.arraycopy(Fbody, 0, result, Fheader.length, Fbody.length);

        return result;
    }

    /**
     * Instantiate an HTTPReqRes element
     *
     * @param request the request in byte[] form
     * @param response the response in byte[] form
     */
    public HTTPReqRes(byte[] request, byte[] response) {
        // TODO: make method to work as with helpers
        this.isRequest = true;
        this.isResponse = true;
        this.setRequest(request);
        this.setResponse(response);
        instances++;
    }

    /**
     * Instantiate an HTTPReqRes element from a <code>IHttpRequestResponsePersisted</code> message
     *
     * <p>--> now changed to create it from a HistoryReference
     *
     * @param message the history reference to access the message
     */
    public HTTPReqRes(HttpMessage message)
            throws MalformedURLException, HttpMalformedHeaderException, DatabaseException {
        this.isRequest = true;
        this.isResponse = true;

        startingMessage = message;

        // --------------------------------------------------------------------------------------------//
        this.setRequest(
                concat_Request(
                        message.getRequestHeader().toString().getBytes(),
                        message.getRequestBody().getBytes()));
        this.setResponse(
                concat_Response(
                        message.getResponseHeader().toString().getBytes(),
                        message.getResponseBody().getBytes()));

        // Qua dovrei prendere un URL, più passaggi per convertire da java.net.URI a
        // org.apache.commons.httpclient.URI
        String readURI = message.getRequestHeader().getURI().toString();
        URL url = new URL(readURI);
        this.setRequest_url(url.toString());

        // utilizzo HttpRequestHeader perchè sembra che httpmessage consenga sempre il RequestHeader
        HttpRequestHeader service = message.getRequestHeader();
        this.setHost(service.getHostName());
        this.setPort(service.getHostPort());
        if (service.isSecure()) {
            this.setProtocol("https");
        } else {
            this.setProtocol("http");
        }

        // Verificare che sia ciò che voglio
        this.body_offset_req = message.getRequestHeader().toString().length();
        this.body_offset_resp = message.getResponseHeader().toString().length();

        this.headers_req.add(message.getRequestHeader().getPrimeHeader());
        System.out.println("Prime req header === " + headers_req.get(0));
        this.headers_req.addAll(toStringList(message.getRequestHeader().getHeaders()));
//        this.headers_req = toStringList(message.getRequestHeader().getHeaders());

        this.headers_resp.add(message.getResponseHeader().getPrimeHeader());
        System.out.println("Prime res header === " + headers_resp.get(0));
        this.headers_resp.addAll(toStringList(message.getResponseHeader().getHeaders()));
//        this.headers_resp = toStringList(message.getResponseHeader().getHeaders());

        instances++;
    }

    /** Converts a List of HttpHeaderField to a List of String since the Burp code used that one */
    private List<String> toStringList(List<HttpHeaderField> lista) {
        String buf;
        List<String> toReturn = new ArrayList<>();
        for (HttpHeaderField item : lista) {
            buf = item.toString();
            toReturn.add(buf);
        }
        return toReturn;
    }

    /**
     * Instantiate an HTTPReqRes element. If a message is a request it does not gather the response
     *
     * @param message an IHTTPRequestResponse message
     * @param isRequest true if the message is a request, false otherwise
     * @param index indice
     */
    public HTTPReqRes(HttpMessage message, boolean isRequest, int index) throws MalformedURLException {
        if (!isRequest) {
            this.isResponse = true;
            this.setResponse(
                    concat_Response(
                            message.getResponseHeader().toString().getBytes(),
                            message.getResponseBody().getBytes()));
            this.headers_resp = new ArrayList<>();
            this.headers_resp.add(message.getResponseHeader().getPrimeHeader());
            System.out.println("Prime res header === " + headers_resp.get(0));
            this.headers_resp.addAll(toStringList(message.getResponseHeader().getHeaders()));


            this.body_offset_resp = message.getResponseHeader().toString().length();
        }

        this.index = index;

        // TODO the request is always present in a IHTTPRequestResponse
        this.isRequest = true;
        this.setRequest(
                concat_Request(
                        message.getRequestHeader().toString().getBytes(),
                        message.getRequestBody().getBytes()));
        this.setRequest_url(message.getRequestHeader().getURI().toString());

        this.headers_req = new ArrayList<>();
        this.headers_req.add(message.getRequestHeader().getPrimeHeader());
        System.out.println("Prime req header === " + headers_req.get(0));
        this.headers_req.addAll(toStringList(message.getRequestHeader().getHeaders()));

        // Qua dovrei prendere un URL, più passaggi per convertire da java.net.URI a
        // org.apache.commons.httpclient.URI
        String readURI = message.getRequestHeader().getURI().toString();
        URL url = new URL(readURI);
        this.setRequest_url(url.toString());
        System.out.println("URL is " + url.toString());

        this.body_offset_req = message.getRequestHeader().toString().length();

        // set host info getHttpService
        HttpRequestHeader service = message.getRequestHeader();
        this.setHost(service.getHostName());
        this.setPort(service.getHostPort());
        if (service.isSecure()) {
            this.setProtocol("https");
        } else {
            this.setProtocol("http");
        }

        instances++;
    }

    /**
     * Function taken from URLEncodedUtils and edited Returns a list of {@link NameValuePair}s
     * parameters.
     *
     * @param buf text to parse.
     * @param charset Encoding to use when decoding the parameters.
     * @param separators element separators.
     * @return a list of {@link NameValuePair} as built from the URI's query portion.
     * @since 4.4
     */
    public static List<NameValuePair> parse_url_query_no_decoding(
            final CharArrayBuffer buf, final Charset charset, final char... separators) {
        Args.notNull(buf, "Char array buffer");
        final TokenParser tokenParser = TokenParser.INSTANCE;
        final BitSet delimSet = new BitSet();
        for (final char separator : separators) {
            delimSet.set(separator);
        }
        final ParserCursor cursor = new ParserCursor(0, buf.length());
        final List<NameValuePair> list = new ArrayList<NameValuePair>();
        while (!cursor.atEnd()) {
            delimSet.set('=');
            final String name = tokenParser.parseToken(buf, cursor, delimSet);
            String value = null;
            if (!cursor.atEnd()) {
                final int delim = buf.charAt(cursor.getPos());
                cursor.updatePos(cursor.getPos() + 1);
                if (delim == '=') {
                    delimSet.clear('=');
                    value = tokenParser.parseToken(buf, cursor, delimSet);
                    if (!cursor.atEnd()) {
                        cursor.updatePos(cursor.getPos() + 1);
                    }
                }
            }
            if (!name.isEmpty()) {
                list.add(new BasicNameValuePair(name, value));
            }
        }
        return list;
    }

    public String getUrlHeader() {
        if (!isRequest) throw new RuntimeException("called getUrlHeader on a response message");

        return this.headers_req.get(0);
    }

    public void setUrlHeader(String url_header) {
        if (!isRequest) throw new RuntimeException("called setUrlHeader on a response message");

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
        if (isRequest
                && (!this.hasBody(isRequest) | this.request == null | this.request.length == 0)) {
            throw new RuntimeException("called getBody, but class is not properly initialized");
        }
        if (!isRequest
                && (!this.hasBody(isRequest) | this.response == null | this.response.length == 0)) {
            throw new RuntimeException("called getBody, but class is not properly initialized");
        }

        if (isRequest) {
            // if asking for the first time, take the body from the message
            if (this.body_req == null)
                this.body_req =
                        Arrays.copyOfRange(this.request, this.body_offset_req, this.request.length);
            return this.body_req;
        } else {
            if (this.body_resp == null)
                this.body_resp =
                        Arrays.copyOfRange(
                                this.response, this.body_offset_resp, this.response.length);
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
     */
    public byte[] build_message(boolean isRequest) {
        String builded = "";
        byte[] body = getBody(isRequest);

        List<String> headers = getHeaders(isRequest);
        String content_header = "Content-Length: " + body.length;
        boolean content_hearder_found = false;

        for (String header : headers) {
            if (header.contains("Content-Length:")) {
                content_hearder_found = true;
                if (body.length == 0)
                    continue; // if Content-Length header found, but message has no body, remove.
                builded += content_header;
            } else {
                builded += header;
            }
            builded += "\r\n";
        }

        if (!content_hearder_found && body.length != 0) {
            builded += content_header + "\r\n";
        }

        builded += "\r\n"; // last row of header before body

        if (body.length != 0) builded += new String(body);

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

    /** Get the original un-edited request message */
    public byte[] getRequest() {
        return request;
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    /** Get the original un-edited response message */
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
     * Get the Name Value Pair list of the query parameters in the url.
     *
     * @return the List of Name Value pairs
     */
    private List<NameValuePair> getNameValuePairUrl() {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        List<NameValuePair> params = new ArrayList<>();

        try {
            URI u = new URI(request_url);
            params = URLEncodedUtils.parse(u, StandardCharsets.UTF_8);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

        return params;
    }

    /**
     * Get the given parameter value from the url of the request messsage
     *
     * @param param the parameter name to be searched
     * @return the value of the parameter
     */
    public String getUrlParam(String param) {
        List<NameValuePair> params = getNameValuePairUrl();

        for (NameValuePair p : params) {
            if (p.getName().equals(param)) {
                return p.getValue();
            }
        }

        return "";
    }

    /**
     * Get the given parameter value from the url of the request messsage.
     *
     * @param disable_url_encode Set to true to get the value of the parameter without URL decoding
     *     it
     * @param param the parameter name to be searched
     * @return the value of the parameter
     */
    public String getUrlParam(String param, boolean disable_url_encode) {
        List<NameValuePair> params = new ArrayList<>();
        if (disable_url_encode) {
            final CharArrayBuffer buffer = new CharArrayBuffer(getUrl().length());
            buffer.append(getUrl());
            params = parse_url_query_no_decoding(buffer, StandardCharsets.UTF_8, '&', ';');
        } else {
            params = getNameValuePairUrl();
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
     * @param regex the regex to execute
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
            params = URLEncodedUtils.parse(new URI(request_url), StandardCharsets.UTF_8);
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

        request_url =
                request_url.replaceAll(
                        "\\Q" + Matcher.quoteReplacement(url.getQuery()) + "\\E",
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
            params = URLEncodedUtils.parse(new URI(request_url), StandardCharsets.UTF_8);
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

        request_url =
                request_url.replaceAll(
                        "\\Q" + Matcher.quoteReplacement(url.getQuery()) + "\\E",
                        new_query);

        updateHeadersWHurl();
    }

    /**
     * Adds an url query parameter to the request url. If parameter already present, concatenate new
     * value to old.
     *
     * @param name the name of the new parameter
     * @param value the value of the new parameter
     */
    public void addUrlParam(String name, String value) {
        if (!isRequest || request_url == null) {
            throw new RuntimeException("Trying to access the url of a response message");
        }

        List<NameValuePair> params = new ArrayList<>();

        try {
            params = URLEncodedUtils.parse(new URI(request_url), StandardCharsets.UTF_8);
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

        request_url =
                request_url.replaceAll(
                        "\\Q" + Matcher.quoteReplacement(url.getQuery()) + "\\E",
                        new_query);

        updateHeadersWHurl();
    }

    /**
     * Get the given parameter value from the head
     *
     * @param isRequest if the message is a request
     * @param param the parameter name to be searched
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
     * @param param the name of the header
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
     * @param regex the regex to execute
     * @param new_value the new value to substitute
     */
    public void editHeadRegex(boolean isRequest, String regex, String new_value) {
        if (!isRequest && !this.isResponse) {
            throw new RuntimeException("tried to edit headers of response not yet received");
        }

        getHeaders(isRequest)
                .replaceAll(
                        header -> {
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
     * @param name the name of the new header
     * @param value the value of the new header
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
     * @param name the name of the header
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
     * Given a message, get the given parameter value from the body, note that it accepts a regular
     * expression, and everything matched will be returned as a value
     *
     * @param isRequest if the message is a request
     * @param regex the parameter to be searched as a regex, everything matched by this will be
     *     returned as a value
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
     * @param regex the regex to execute
     * @param new_value the new value to substitute
     */
    public void editBodyRegex(boolean isRequest, String regex, String new_value) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(new String(getBody(isRequest), StandardCharsets.UTF_8));

        String new_body = matcher.replaceFirst(new_value);
        setBody(isRequest, new_body);
    }

    /**
     * Append to the body of the message the given value. If the message doesn't have a body it
     * creates it.
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

    /** Updates the headers in this request message with the acctual url value */
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

        // if (url.getRef() != null) {
        //    new_header_0 += "#" + url.getRef();
        // }

        new_header_0 += " " + url.getProtocol().toUpperCase();
        new_header_0 += "/" + header_0[2].split("/")[1];

        String new_header_1 = "Host: " + url.getHost();

        port = url.getPort();

        System.out.println("La porta è settata a --> " + url.getPort());

        if (port != -1) {
            new_header_1 += ":" + port;
        }

        int hostIndex = -1;
        for (int i = 0; i < headers_req.size(); i++) {
            if (headers_req.get(i).toLowerCase().contains("host")) {
                hostIndex = i;
                break;
            }
        }

        if (hostIndex == -1) {
            throw new RuntimeException("could not find Host header in header");
        }


/*
        for (int i = 0; i < headers_req.size(); i++) {
            if (headers_req.get(i).contains("Host")) {
                System.err.println("TROVATO Host header in header --> " + i);
                break;
            }
        }

        if (!headers_req.get(1).contains("Host")) {
            throw new RuntimeException("could not find Host header in header");
        }

 */

        headers_req.set(0, new_header_0);
        headers_req.set(1, new_header_1);


    }

    /**
     * Function to check if the given message matches a message_type
     *
     * @param msg_type the message type to check against it
     * @param is_request tells whether the message you are checking is a request or a response
     * @return true or false, if matched or not respectively
     */
    public boolean matches_msg_type(MessageType msg_type, boolean is_request) {

        boolean matchedMessage = false;
        try {

            /*
            System.err.println("------------------------------------------");
            for (Check c : msg_type.checks){
                System.err.println(c.toStringExtended());
            }
            System.err.println(msg_type.getByRequest);

            System.err.println("------------------------------------------");
            */


            /* If the response message name is searched, the getByResponse will be true.
             * so messageIndex have to search for the request, and then evaluate the response
             */
            if (msg_type.getByResponse) {
                if (!isResponse){
                    System.err.println("Uscito subito da matches_msg_type");
                    return false; // both request and response have to be present
                }
                System.err.println("-------------------------------------------> matches_msg_type 2");
                matchedMessage =
                        Tools.executeChecks(
                                msg_type.checks, this, true, new ArrayList<>() // TODO: fix
                                );
            } else if (msg_type.getByRequest) {
                if (!isResponse){
                    return false; // both request and response have to be present
                }
                System.err.println("-------------------------------------------> matches_msg_type 3");
                matchedMessage =
                        Tools.executeChecks(
                                msg_type.checks, this, false, new ArrayList<>() // TODO: fix
                                );
            } else {
                // this check is done to avoid matching request messages when intercepting a
                // response
                if (is_request != msg_type.msg_to_process_is_request){
                    return false;
                }
                if (!msg_type.isRequest && !isResponse){
                    System.err.println("-------------------------------------------> matches_msg_type 4");
                    return false; // this message is not containing a response
                }

                System.err.println("-------------------------------------------> matches_msg_type 5");

                System.err.println(this);
                System.err.println("-------------------------------------------");


                matchedMessage =
                        Tools.executeChecks(
                                msg_type.checks,
                                this,
                                msg_type.isRequest,
                                new ArrayList<>() // TODO: fix
                                );
            }
        } catch (Exception e) {
            System.err.println("errore in matched_messages ha causato un eccezione");
            System.err.println(e.getMessage());
        }
        System.err.println("return di matches_msg_type is " + matchedMessage);
        return matchedMessage;
    }

    /**
     * Returns a string representation of all the headers of the message
     *
     * @param isRequest select the request or the response
     */
    public String getHeadersString(boolean isRequest) {
        List<String> headers_string = getHeaders(isRequest);
        return String.join("\r\n", headers_string);
    }

    /** An enum representing the possible message sections */
    public enum MessageSection {
        HEAD,
        BODY,
        URL,
        RAW;

        /**
         * Function that given a message section in form of String, returns the corresponding
         * MessageSection enum value
         *
         * @param input the input string
         * @return the MessageSection enum value
         * @throws ParsingException if the input does not correspond to any of the possible
         *     messagesections
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
