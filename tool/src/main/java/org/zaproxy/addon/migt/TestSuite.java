package org.zaproxy.addon.migt;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.text.StringEscapeUtils;

/** Class to store a TestSuite */
public class TestSuite {
    String name;
    String description;
    List<Test> tests;

    /** Instantiate the TestSuite */
    public TestSuite() {
        this.name = "";
        this.description = "";
        this.tests = new ArrayList<>();
    }

    /**
     * Instantiate a TestSuite
     *
     * @param name the name of the test suite
     * @param description the description of the test suite
     * @param tests the list of the tests
     */
    public TestSuite(String name, String description, List<Test> tests) {
        this.name = name;
        this.description = description;
        this.tests = tests;
    }

    /**
     * This function logs the test suite results and calls the logging function of every test.
     *
     * @param log_folder_path the log path containing all the mig-t logs
     */
    public void log_test_suite(String log_folder_path) {
        String timestamp = new SimpleDateFormat("yyyy_MM_dd_HH_mm").format(new java.util.Date());
        String test_log_folder = log_folder_path + "/" + timestamp + "/suite_" + this.name + "/";

        File directory = new File(test_log_folder);
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                System.err.println("cannot create log directory at " + test_log_folder);
            }
        }

        String log_content = "";
        log_content += "| name | description | type | result | applicable |\n";
        log_content += "|-----------|-------------|------|--------|------------|\n";

        for (Test t : tests) {
            log_content +=
                    "|"
                            + t.name
                            + "|"
                            + t.description
                            + "|"
                            + (t.isActive ? "active" : "passive")
                            + "|"
                            + t.success
                            + "|"
                            + t.applicable
                            + "|\n";

            t.logTest(log_folder_path);
        }

        File log_message = new File(test_log_folder + "results.md");
        try {
            FileWriter fw = new FileWriter(log_message.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(log_content);
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        String log_content_csv = "";
        log_content_csv += "name,description,type,result,applicable\n";
        for (Test t : tests) {
            log_content_csv +=
                    StringEscapeUtils.escapeJava(t.name.replaceAll(",", ""))
                            + ","
                            + StringEscapeUtils.escapeJava(t.description.replaceAll(",", ""))
                            + ","
                            + (t.isActive ? "active" : "passive")
                            + ","
                            + t.success
                            + ","
                            + t.applicable
                            + "\n";
        }

        File log_suite_csv = new File(test_log_folder + "results.csv");
        try {
            FileWriter fw = new FileWriter(log_suite_csv.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(log_content_csv);
            bw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public List<Test> getTests() {
        return tests;
    }
}
