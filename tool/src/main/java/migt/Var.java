package migt;

/**
 * The class storing the variables used in the test and sessions
 */
public class Var {
    public String name;
    public String value;
    public byte[] message;
    public boolean isMessage; // tells if a variable contains a message

    /**
     * Istantiate a Var object
     */
    public Var() {
        this.name = "";
        this.value = "";
        this.isMessage = false;
    }

    public Var(String name, String value, Boolean isMessage) {
        this.name = name;
        this.value = value;
        this.isMessage = isMessage;
    }
}
