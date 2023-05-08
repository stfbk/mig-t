package burp;

/**
 * This class is the Parent class inherited by all modules. It provides some methods and parameters to be
 * used by other classes
 */
public class Module {
    boolean result = true;
    boolean applicable = false;
    IExtensionHelpers helpers;
    API api;

    public Module() {

    }

    public Module(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    /**
     * Placeholder of a loader method for the API. This method should load all the things needed by the module
     * from the previous module where the API is imported from.
     *
     * @param api the imported API
     */
    public void loader(API api) {

    }

    /**
     * Placeholder of a exporter function. This function should return the API object after it is edited.
     *
     * @return the edited API
     * @throws ParsingException
     */
    public API exporter() throws ParsingException {
        return null;
    }

    /**
     * Sets the result of a child module to this one. For convenience, returns the result of the module
     *
     * @param module the module to save the result from
     * @param <T>    The module class
     */
    public <T extends Module> boolean setResult(T module) {
        if (!module.applicable) {
            this.applicable = false;
            this.result = false;
        } else if (!module.result) {
            this.result = false;
        }
        return module.result;
    }
}
