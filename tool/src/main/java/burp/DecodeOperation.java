package burp;

import java.util.Collections;
import java.util.List;

/**
 * This class stores a decode operation
 */
public class DecodeOperation extends Module {
    String decoded_content; // the decoded content
    String decode_target; // aka decode_param how to decode the raw content
    Utils.MessageSection from; // where the raw content is
    List<Utils.Encoding> encodings; // the list of encoding to decode and rencode
    Utils.MessageOpType type; // the type of the decoded param
    API api;

    public DecodeOperation(
            Utils.MessageSection from,
            String decode_target,
            List<Utils.Encoding> encodings,
            Utils.MessageOpType type) {
        this.from = from;
        this.decode_target = decode_target;
        this.encodings = encodings;
        this.type = type;
    }

    public void loader(Operation_API api, IExtensionHelpers helpers) throws ParsingException {
        // load api, extract needed things
        this.helpers = helpers;
        this.api = api;

        decoded_content = Encoding.decodeParam(
                helpers, from, encodings, api.message, api.is_request, decode_target);
    }

    @Override
    public Operation_API exporter() throws ParsingException {
        Collections.reverse(encodings); // Set the right order for encoding
        String encoded = Encoding.encode(encodings, decoded_content, helpers);

        byte[] edited_message = Utils.editMessageParam(
                helpers,
                decoded_content,
                from,
                ((Operation_API) api).message,
                ((Operation_API) api).is_request,
                encoded,
                true);

        if (edited_message != null) {
            if (((Operation_API) api).is_request) {
                ((Operation_API) api).message.setRequest(edited_message);
            } else {
                ((Operation_API) api).message.setResponse(edited_message);
            }
            /*
            if (op.processed_message_service != null) {
                messageInfo.setHttpService(op.processed_message_service);
            }
            */
        }

        return ((Operation_API) api);
    }
}
