package org.zaproxy.addon.migt;

import java.awt.BorderLayout;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.HttpPanelRequest;
import org.zaproxy.zap.extension.httppanel.HttpPanelResponse;

public class ReqResPanel extends AbstractPanel {
    private static final long serialVersionUID = 1L;
    private HttpPanelRequest httpPanelRequest;
    private HttpPanelResponse httpPanelResponse;

    public ReqResPanel() {
        this.setName("ReqResPanel");
        this.setLayout(new BorderLayout());

        httpPanelRequest = new HttpPanelRequest(false, "Request Panel");
        // httpPanelRequest.loadConfig(new ZapXmlConfiguration());

        httpPanelResponse = new HttpPanelResponse(false, "Response Panel");
        // httpPanelResponse.loadConfig(new ZapXmlConfiguration());

        this.add(httpPanelRequest, BorderLayout.NORTH);
        this.add(httpPanelResponse, BorderLayout.SOUTH);
    }

    public void setMessage(HTTPReqRes msg, boolean isRequest) throws HttpMalformedHeaderException {
        HttpMessage httpm = new HttpMessage();
        if (isRequest) {
            httpm.setRequestHeader(msg.Req_header);
            httpm.setRequestBody(msg.Req_body);
            httpPanelRequest.setMessage(httpm);
        } else {
            httpm.setResponseHeader(msg.Res_header);
            httpm.setResponseBody(msg.Res_body);
            httpPanelResponse.setMessage(httpm);
        }
    }
}
