package org.zaproxy.addon.migt;

import javax.swing.JPanel;
import org.json.JSONObject;

/**
 * This class is the Parent class inherited by all modules. It provides some methods and parameters
 * to be used by other classes
 */
public class Module {
    // These variables should be present in each module
    boolean result = true;
    boolean applicable = false;
    API api; // the api of this module
    API imported_api; // the api imported from a previous module

    /** When the module doesn't require any input */
    public Module() {}

    /**
     * Used when the module requires inputs from the JSON language. Instantiate the module by
     * parsing a JSONObject which contains the JSON inputs.
     *
     * @param json_module the json input for this module
     */
    public Module(JSONObject json_module) {
        // Parse
    }

    /**
     * This function should be called to check that after an initialization of a module all the
     * necessary parameters are set correctly. And the JSON has been parsed correctly with all the
     * required tags present.
     */
    public void validate() throws ParsingException {}

    /** Method used to get the API object of this module to be used in other modules. */
    public <T extends API> T getAPI() {
        return null;
    }

    /**
     * Method used to set the API object of this module, when it is edited or simply to initiate it.
     */
    public void setAPI(API api) {}

    /**
     * Placeholder of a loader method for the API. This method should load all the things needed by
     * the module from the previous module where the API is imported from.
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
     * Placeholder of a exporter function. This function should return the API object to where it
     * has been loaded after it has been edited. There is no need to call the exporter if the API is
     * not edited.
     *
     * @return the edited API
     * @throws ParsingException
     */
    public API exporter() throws ParsingException {
        return null;
    }

    /**
     * Update the result of this module from a child module. For convenience, returns the result of
     * the module
     *
     * @param module the module to save the result from
     * @param <T> The module class
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

    public void setApplicable(boolean applicable) {
        this.applicable = applicable;
    }

    /**
     * Get the result of this module
     *
     * @return the result of the module
     */
    public boolean getResult() {
        return this.result & this.applicable;
    }

    public void setResult(boolean result) {
        this.result = result;
    }

    /**
     * Execute this module and give a result
     *
     * @return the result of this module
     */
    public void execute() {
        throw new RuntimeException("Called execute method of root Module");
    }

    /**
     * This method should return a graphical representation of the module, used to visualize the
     * module from the GUI. The representation should include useful informations about what the
     * module did, or which errors were found during execution
     *
     * @return a JPanel object containing the graphical interface of this module
     */
    public JPanel view() {
        return null;
    }
}
