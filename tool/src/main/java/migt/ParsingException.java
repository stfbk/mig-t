package migt;

/**
 * Exception raised when the parsing of the language fails
 *
 * @author Matteo Bitussi
 */
public class ParsingException extends Exception {
    /**
     * Raised when there is a problem in the parsing of the json
     *
     * @param errorMessage the error message to be displayed
     */
    public ParsingException(String errorMessage) {
        super(errorMessage);
    }
}
