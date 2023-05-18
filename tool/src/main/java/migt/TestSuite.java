package migt;

import java.util.ArrayList;
import java.util.List;

/**
 * Class to store a TestSuite
 *
 * @author Matteo Bitussi
 */
public class TestSuite {
    String name;
    String description;
    List<Test> tests;
    Test currentTest;
    boolean metadata = false;

    /**
     * Instantiate the TestSuite
     */
    public TestSuite() {
        this.name = "";
        this.description = "";
        this.tests = new ArrayList<>();

        this.currentTest = null;
    }

    /**
     * Instantiate a TestSuite
     *
     * @param name        the name of the test suite
     * @param description the description of the test suite
     * @param tests       the list of the tests
     */
    public TestSuite(String name, String description, List<Test> tests) {
        this.name = name;
        this.description = description;
        this.tests = tests;

        this.currentTest = null;
    }

    public List<Test> getTests() {
        return tests;
    }
}
