package org.zaproxy.addon.migt;

/** The class storing the variables used in the test and sessions */
public class Var {
    public String name;
    public Object value;

    /** Instantiate a Var object */
    public Var() {
        this.name = "";
        this.value = "";
    }

    /**
     * Constructor for variables that have a String Value
     *
     * @param name the name of the var
     * @param value the String value of the var
     */
    public Var(String name, String value) {
        this.name = name;
        this.value = value;
    }

    /**
     * Constructor for variables that have a message value
     *
     * @param name the name of the variable
     * @param message the value of the message as String
     */
    public Var(String name, byte[] message) {
        this.name = name;
        this.value = message;
    }

    /**
     * Constructor for variable that have a JSON array value
     *
     * @param name the name of the variable
     * @param value the value of the JSON array
     */
    public Var(String name, Object[] value) {
        this.name = name;

        int len = value.length;
        this.value = new String[len];

        int c = 0;

        for (Object o : value) {
            if (!(o instanceof String)) {
                throw new RuntimeException("invalid value in saved array, can only save strings");
            }
            ((String[]) this.value)[c++] = (String) o;
        }
    }

    /**
     * Get the type of the value of the variable
     *
     * @return the type of the value of the variable
     */
    public VarType getType() {
        if (value instanceof String) {
            return VarType.STRING;
        } else if (value instanceof byte[]) {
            return VarType.MESSAGE;
        } else if (value instanceof String[]) {
            return VarType.STRING_ARRAY;
        } else {
            throw new RuntimeException("The type of the variable is not valid");
        }
    }

    /**
     * Use this function to get the value of this variable expecting that it is a String
     *
     * @return the string value of this variable only if it is a string
     * @throws ParsingException if the value of this variable is not a string
     */
    public String get_value_string() throws ParsingException {
        if (this.getType() != VarType.STRING) {
            throw new ParsingException("Variable " + this.name + "'s value is not a string");
        }

        return (String) value;
    }

    /**
     * Use this function to get the value of this variable expecting that it is storing an HTTP
     * message
     *
     * @return the http message in <type>byte[]</type> format
     * @throws ParsingException if the value of the variable is not a message
     */
    public byte[] get_value_message() throws ParsingException {
        if (this.getType() != VarType.MESSAGE) {
            throw new ParsingException("Variable " + this.name + "'s value is not a message");
        }

        return (byte[]) value;
    }

    /** Enum containing all the possible types of variables */
    public enum VarType {
        STRING,
        MESSAGE,
        STRING_ARRAY
    }
}
