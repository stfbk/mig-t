package burp;

/**
 * Check Object class. This object is used in Operations to check that a parameter or some text is in as specified.
 *
 * @author Matteo Bitussi
 */
public class Check {
    String what; // what to search
    Utils.CheckOps op; // the check operations
    Utils.MessageSection in; // the section over which to search
    String op_val;
    boolean isParamCheck = false; // specifies if what is declared in what is a parameter name

    public void setWhat(String what) {
        this.what = what;
    }

    public void setOp(Utils.CheckOps op) {
        this.op = op;
    }

    @Override
    public String toString() {
        return "check: " + what + (op == null ? "" : " " + op + ": " + op_val);
    }
}
