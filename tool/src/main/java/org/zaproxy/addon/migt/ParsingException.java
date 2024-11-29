package org.zaproxy.addon.migt;

/** Exception raised when the parsing of the language fails */
public class ParsingException extends Exception {
//    private static final long serialVersionUID = 1L;

    /**
     * Raised when there is a problem in the parsing of the json
     *
     * @param errorMessage the error message to be displayed
     */
    public ParsingException(String errorMessage) {
        super(errorMessage);
    }
}
