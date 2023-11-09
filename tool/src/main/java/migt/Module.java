package migt;

import burp.IExtensionHelpers;
import org.json.JSONObject;

/**
 * This class is the Parent class inherited by all modules. It provides some methods and parameters to be
 * used by other classes
 */
public class Module {
    // These variables should be present in each module
    boolean result = true;
    boolean applicable = false;
    IExtensionHelpers helpers;
    API api; // the api of this module
    API imported_api; // the api imported from a previous module

    public Module() {

    }

    /**
     * Instantiate the module by parsing a JSONObject
     *
     * @param json_module
     */
    public Module(JSONObject json_module) {
        // Parse
    }

    public Module(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    /**
     * This function should be called to check that after an initialization of a module all the necessary parameters
     * are set correctly. And the JSON has been parsed correctly with all the required tags present.
     */
    public void validate() throws ParsingException {

    }

    /**
     * Method used to get the API object of this module to be used in other modules.
     */
    public <T extends API> T getAPI() {
        return null;
    }

    /**
     * Method used to set the API object of this module, when it is edited or simply to initiate it.
     */
    public void setAPI(API api) {

    }

    /**
     * Placeholder of a loader method for the API. This method should load all the things needed by the module
     * from the previous module where the API is imported from.
     *
     * @param api the imported API
     */
    public void loader(API api) {
        if (api == null) {
            throw new RuntimeException("loaded api is null");
        }
        this.imported_api = api;
    }

    /**
     * Placeholder of a exporter function. This function should return the API object to where it has been loaded after
     * it has been edited. There is no need to call the exporter if the API is not edited.
     *
     * @return the edited API
     * @throws ParsingException
     */
    public API exporter() throws ParsingException {
        return null;
    }

    /**
     * Update the result of this module from a child module. For convenience, returns the result of the module
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

    /**
     * Get the result of this module
     *
     * @return the result of the module
     */
    public boolean getResult() {
        return this.result;
    }
}
