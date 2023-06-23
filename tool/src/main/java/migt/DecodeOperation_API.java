package migt;

public class DecodeOperation_API extends API {
    public Utils.DecodeOpType type; // the type of the decoded param

    public String jwt_header;
    public String jwt_payload;
    public String jwt_signature;
    public String txt;
    public String xml;


    public DecodeOperation_API() {

    }

    public DecodeOperation_API(DecodeOperation dop) {
        type = dop.type;
        switch (dop.type) {
            case NONE:
                txt = dop.decoded_content;
                break;
            case JWT:
                jwt_header = dop.jwt.header;
                jwt_payload = dop.jwt.payload;
                jwt_signature = dop.jwt.signature;
                break;
            case XML:
                xml = dop.decoded_content;
                break;
        }
    }

    public String getDecodedContent(Utils.DecodeOperationFrom dopfrom) throws ParsingException {
        switch (dopfrom) {
            case HEAD:
                throw new ParsingException("cannot decode from header in a recursive decode");
            case BODY:
                throw new ParsingException("cannot decode from body in a recursive decode");
            case URL:
                throw new ParsingException("cannot decode from url in a recursive decode");
            case JWT_HEADER:
                if (type != Utils.DecodeOpType.JWT)
                    throw new ParsingException("cannot decode in a jwt header if previous decode was not a jwt");
                return jwt_header;

            case JWT_PAYLOAD:
                if (type != Utils.DecodeOpType.JWT)
                    throw new ParsingException("cannot decode in a jwt payload if previous decode was not a jwt");
                return jwt_payload;

            case JWT_SIGNATURE:
                if (type != Utils.DecodeOpType.JWT)
                    throw new ParsingException("cannot decode in a jwt signature if previous decode was not a jwt");
                return jwt_signature;
            default:
                throw new UnsupportedOperationException("invalid Decode operation from");
        }
    }
}
