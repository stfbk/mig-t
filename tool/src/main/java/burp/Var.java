package burp;

/**
 * The class storing the variables used in the test and sessions
 *
 * @author Matteo Bitussi
 */
public class Var {
    public String name;
    public String value;
    public byte[] message;
    public boolean isMessage; // tells if a variable contains a message
    public IHttpService service_info;

    /**
     * Istantiate a Var object
     */
    public Var() {
        this.name = "";
        this.value = "";
        this.isMessage = false;
    }
}
