package org.zaproxy.addon.migt;

public class DecodeOperation_API extends API {
    public DecodeOperation.DecodeOpType type; // the type of the decoded param

    public JWT jwt;
    public String txt;
    public String xml;

    public DecodeOperation_API() {
        init();
    }

    public DecodeOperation_API(DecodeOperation dop) {
        init();
        type = dop.type;
        switch (dop.type) {
            case NONE:
                txt = dop.decoded_content;
                break;
            case JWT:
                jwt = dop.jwt;
                break;
            case XML:
                xml = dop.decoded_content;
                break;
        }
    }

    public void init() {
        jwt = new JWT();
    }

    public String getDecodedContent(DecodeOperation.DecodeOperationFrom dopfrom)
            throws ParsingException {
        switch (dopfrom) {
            case HEAD:
                throw new ParsingException("cannot decode from header in a recursive decode");
            case BODY:
                throw new ParsingException("cannot decode from body in a recursive decode");
            case URL:
                throw new ParsingException("cannot decode from url in a recursive decode");
            case JWT_HEADER:
                if (type != DecodeOperation.DecodeOpType.JWT)
                    throw new ParsingException(
                            "cannot decode in a jwt header if previous decode was not a jwt");
                return jwt.header;

            case JWT_PAYLOAD:
                if (type != DecodeOperation.DecodeOpType.JWT)
                    throw new ParsingException(
                            "cannot decode in a jwt payload if previous decode was not a jwt");
                return jwt.payload;

            case JWT_SIGNATURE:
                if (type != DecodeOperation.DecodeOpType.JWT)
                    throw new ParsingException(
                            "cannot decode in a jwt signature if previous decode was not a jwt");
                return jwt.signature;
            default:
                throw new UnsupportedOperationException("invalid Decode operation from");
        }
    }
}
