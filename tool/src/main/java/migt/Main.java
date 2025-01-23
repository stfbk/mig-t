package migt;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.google.gson.Gson;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.openqa.selenium.WebDriver;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.*;
import java.util.List;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sets a JTextArea as an output of an OutputStream, used by the redirect of the stdout and stderr
 */
class CustomOutputStream extends OutputStream {
    private final JTextArea textArea;

    public CustomOutputStream(JTextArea textArea) {
        this.textArea = textArea;
    }

    @Override
    public void write(int b) {
        // Redirect the byte written to the OutputStream to the JTextArea
        retry:
        try {
            textArea.append(String.valueOf((char) b));
            textArea.setCaretPosition(textArea.getDocument().getLength()); // Auto-scroll to the bottom
        } catch (java.lang.Error e) {
            // for some reason write lock acquire is interrupted sometimes
            break retry; // TODO: fix
        }
    }
}

/**
 * This class contains the GUI for the plugin, also a lot of functionality methods
 */
public class Main extends JSplitPane {
    protected static DefaultTableModel resultTableModel;
    protected static DefaultTableModel testTableModel;
    final Object waiting = new Object();
    final String LOG_FOLDER = "logs/";
    private final String[] foundTableColNames = {"Op. num", "Message Type", "message section", "check/regex", "index", "result"};
    private final String[] testSuiteColNames = {
            "Test name",
            "Description",
            "References",
            "Statement in Ref. to Test",
            "Affected Entity",
            "Mitigations",
            "Result"};
    private final Object[][] foundData = {};
    private final Object lock2 = new Object();
    public ArrayList<HTTPReqRes> interceptedMessages;
    String SAVE_FILE_PATH = "";
    String RECORD_FILE_PATH = "";
    boolean FILTERING = true;
    String MSG_DEF_PATH = "msg_def.json";
    String CONFIG_FILE_PATH = "config.json";
    //GUI
    JTable resultTable;
    JTable testTable;
    JPanel trackContainer;
    JPanel inputContainer;
    JLabel lblTrack;
    JLabel lblnextTestBrowser;
    JLabel lblInfo;
    JLabel lblOutput;
    JLabel lbldriver;
    JButton btnTestTrack;
    JButton btnselectChrome;
    JButton btnselectFirefox;
    JButton btnExecuteSuite;
    JButton btnSetRecording;
    JButton btnLoadMessages;
    JButton btnSetOffline;
    JButton btnExecuteTrack;
    JButton btnSaveToFile;
    JButton btndriverSelector;
    JButton btnReadJSON;
    JTextArea txtScript;
    JTextArea txtSearch;
    JTextArea txtSessionConfig;
    JTextArea txt_out_debug_tab;
    JTextArea txt_err_debug_tab;
    JFileChooser driverSelector;
    JSplitPane splitPane;
    IMessageEditor messageViewer;
    IMessageEditorController controller;
    JTabbedPane top_tabbed;
    JTabbedPane bot_tabbed;
    Map<String, Integer> bot_tabs_index;
    HTTPReqRes viewedMessage;
    IBurpExtenderCallbacks callbacks;
    List<String> sessions_names;
    Map<String, String> session_port;
    Session defaultSession;
    TestSuite testSuite;
    boolean INTERCEPT_ENABLED;
    boolean recording = false;
    boolean OFFLINE = false;
    boolean SAVE_TO_FILE = false;
    Operation actual_operation;
    ExecuteActives ex;
    List<MessageType> messageTypes;
    private Integer DEFAULT_PORT = 8080;
    private String DRIVER_PATH;
    private List<Test> actives;
    Map<String, JTextArea> sessions_text;
    private List<Test> passives;
    private Thread active_ex;
    private boolean active_ex_finished = false;

    /**
     * Constructor of the plugin UI
     */
    public Main() {
        super(JSplitPane.VERTICAL_SPLIT);
        //initialize vars
        init();

        set_std_out_redirect();

        this.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top part of the UI ------------------------------------------------------------------------------------------
        GridBagLayout top_layout = new GridBagLayout();
        top_layout.columnWidths = new int[]{230, 230, 230, 230, 100, 100, 100};
        top_layout.rowHeights = new int[]{20, 48, 48, 48, 48};
        top_layout.columnWeights = new double[]{1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0};
        top_layout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0};

        trackContainer = new JPanel();
        trackContainer.setLayout(top_layout);

        setup_tab_track();
        setup_tab_butons();

        this.setTopComponent(trackContainer);

        // Bottom part -------------------------------------------------------------------------------------------------

        GridBagLayout bot_layout = new GridBagLayout();
        bot_layout.columnWidths = new int[]{500, 500, 100};
        bot_layout.rowHeights = new int[]{15, 20, 20, 20, 30};
        bot_layout.columnWeights = new double[]{Double.MIN_VALUE, 0.0};
        bot_layout.rowWeights = new double[]{0.0, Double.MIN_VALUE, 0.0, 0.0, 0.0};

        bot_tabbed = new JTabbedPane();

        JPanel tab_input_json = setup_tab_input_json(bot_layout);
        bot_tabs_index.put("Input JSON", 0);
        bot_tabbed.addTab("Input JSON", tab_input_json);

        JScrollPane tab_suite_result = setup_tab_suite_result(bot_layout);
        bot_tabs_index.put("Test Suite Result", 1);
        bot_tabbed.addTab("Test Suite Result", tab_suite_result);

        JSplitPane tab_test_result = setup_tab_test_result(bot_layout);
        bot_tabs_index.put("Test Result", 2);
        bot_tabbed.addTab("Test Result", tab_test_result);

        JPanel tab_session_config = setup_tab_session_config(bot_layout);
        bot_tabs_index.put("session config", 3);
        bot_tabbed.addTab("session config", tab_session_config);

        JPanel tab_debug_panel = setub_tab_debug(bot_layout);
        bot_tabs_index.put("debug tab", 4);
        bot_tabbed.addTab("debug tab", tab_debug_panel);

        //Set Bottom Part
        this.setBottomComponent(bot_tabbed);

        readMsgDefFile();
        readConfigFile();

        //--------------------------------------
        //DRIVER_PATH = Main.class.getClassLoader().getResource("driver/geckodriver").getPath();
        //DRIVER_PATH = JOptionPane.showInputDialog(null, "enter the driver path:");
        DRIVER_PATH = "/root/geckodriver";
        //--------------------------------------

        if (!DRIVER_PATH.equals("")) {
            lbldriver.setText("Driver Selected");
            btndriverSelector.setBackground(Color.GREEN);
            btnTestTrack.setEnabled(true);
        }
    }

    /**
     * Function used to add an item to the resultTableModel. Contains the results of the tests
     *
     * @param data the string array containing the data, also a row
     */
    private static void addItem(String[] data) {
        resultTableModel.addRow(data);
    }

    public void init() {
        interceptedMessages = new ArrayList<>();
        testSuite = new TestSuite();
        passives = new ArrayList<>();
        actives = new ArrayList<>();
        sessions_names = new ArrayList<>();
        INTERCEPT_ENABLED = false;
        sessions_text = new HashMap<>();
        messageTypes = new ArrayList<>();
        session_port = new HashMap<>();
        bot_tabs_index = new HashMap<>();
        txt_out_debug_tab = new JTextArea();
        txt_err_debug_tab = new JTextArea();
    }

    public boolean is_driver_path_valid() {
        WebDriver driver = ExecuteTrack.init_driver(
                !btnselectChrome.isEnabled(),
                Integer.toString(DEFAULT_PORT),
                DRIVER_PATH,
                true);

        boolean res = driver != null;
        if (!res) {
            System.out.println("The selenium driver executable is not working");
        } else {
            driver.quit();
        }

        driver = null; // Free up
        return res;
    }

    /**
     * Set a redirect of the stdout and stderr to the txtboxes in the debug tab of the GUI
     */
    private void set_std_out_redirect() {
        // Stdout out redirect
        PrintStream printStream = new PrintStream(
                new CustomOutputStream(txt_out_debug_tab));
        System.setOut(printStream);

        // stderr out redirect
        PrintStream printStream_err = new PrintStream(
                new CustomOutputStream(txt_err_debug_tab));
        System.setErr(printStream_err);
    }

    /**
     * Function used to read the message definition file
     */
    private void readMsgDefFile() {
        File msg_def_file = new File(MSG_DEF_PATH);
        try {
            if (msg_def_file.createNewFile()) {
                // if file does not exist
                FileWriter w = new FileWriter(MSG_DEF_PATH);
                w.write(Tools.getDefaultJSONMsgType());
                w.close();
            }

            // read content
            StringBuilder content = new StringBuilder();
            Scanner myReader = new Scanner(msg_def_file);

            while (myReader.hasNextLine()) {
                content.append(myReader.nextLine());
            }
            myReader.close();
            messageTypes = Tools.readMsgTypesFromJson(content.toString()); // load messsage types

        } catch (ParsingException e) {
            lblOutput.setText("Invalid message type in message type definition file");
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
            lblOutput.setText("cannot create message definition file");
        }
    }

    /**
     * Function used to read the json config file
     */
    private void readConfigFile() {
        File config_file = new File(CONFIG_FILE_PATH);
        try {
            if (!config_file.createNewFile()) {
                StringBuilder content = new StringBuilder();
                Scanner myReader = new Scanner(config_file);
                while (myReader.hasNextLine()) {
                    content.append(myReader.nextLine());
                }
                myReader.close();

                JSONObject obj = new JSONObject(content.toString());
                String last_driver_path = obj.getString("last_driver_path");
                String last_used_browser = obj.getString("last_browser_used");
                DEFAULT_PORT = obj.getInt("default_port");

                if (!last_driver_path.isEmpty()) {
                    DRIVER_PATH = last_driver_path;
                }

                switch (last_used_browser) {
                    case "firefox": {
                        btnselectChrome.setEnabled(true);
                        btnselectFirefox.setEnabled(false);
                        break;
                    }
                    case "chrome": {
                        btnselectChrome.setEnabled(false);
                        btnselectFirefox.setEnabled(true);
                        break;
                    }
                }
            } else {
                FileWriter w = new FileWriter(CONFIG_FILE_PATH);
                w.write(Tools.getDefaultJSONConfig());
                w.close();
            }
        } catch (IOException e) {
            lblOutput.setText("cannot create message definition file: " + e);
        } catch (JSONException e) {
            lblOutput.setText("Invalid config file: " + e);
        }
    }

    /**
     * Function that edits the config file.
     *
     * @param key   the key of the config to change
     * @param value the new value of the config
     */
    private void editConfigFile(String key, String value) {
        File config_file = new File(CONFIG_FILE_PATH);
        try {
            if (config_file.createNewFile()) {
                FileWriter w = new FileWriter(CONFIG_FILE_PATH);
                w.write(Tools.getDefaultJSONConfig());
                w.close();
            }

            StringBuilder content = new StringBuilder();
            Scanner myReader = new Scanner(config_file);
            while (myReader.hasNextLine()) {
                content.append(myReader.nextLine());
            }
            myReader.close();

            JSONObject obj = new JSONObject(content.toString());
            obj.remove(key);
            obj.put(key, value);

            FileWriter w = new FileWriter(CONFIG_FILE_PATH);
            w.write(obj.toString());
            w.close();
        } catch (IOException e) {
            lblOutput.setText("cannot create message definition file: " + e);
        } catch (JSONException e) {
            lblOutput.setText("Invalid config file: " + e);
        }
    }

    /**
     * This function parses the given jsonInput string of the language
     *
     * @param jsonInput the json input
     */
    protected void readJSONinput(String jsonInput) {
        sessions_names.clear();
        txtSearch.setBorder(BorderFactory.createEmptyBorder());
        setJSONError(false, "");

        try {
            JSONObject obj = new JSONObject(jsonInput);
            List<Test> tests = new ArrayList<>();

            //Getting Test suite data
            String suite_name = obj.getJSONObject("test suite").getString("name");
            String suite_description = obj.getJSONObject("test suite").getString("description");

            if (obj.getJSONObject("test suite").has("filter messages")) {
                FILTERING = obj.getJSONObject("test suite").getBoolean("filter messages");
            }

            //Array of Tests
            JSONArray arrTests = obj.getJSONArray("tests");
            for (int i = 0; i < arrTests.length(); i++) {
                JSONObject act_test = arrTests.getJSONObject(i).getJSONObject("test");

                Test test = new Test(act_test, messageTypes);
                tests.add(test);

                for (Session s : test.sessions) {
                    if (!sessions_names.contains(s.name)) {
                        sessions_names.add(s.name);
                        session_port.put(s.name, DEFAULT_PORT.toString()); // set default port to session
                    }
                }
            }
            updateSessionTabs();
            updateTxtSessionConfig();

            this.testSuite = new TestSuite(suite_name, suite_description, tests);
            lblInfo.setText("JSON read successfully, Test Suite Object has been created");

        } catch (ParsingException e) {
            e.printStackTrace();

            setJSONError(true, "Problem in parsing JSON: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();

            setJSONError(true, "problem in reading json test suite");
        }
    }

    /**
     * This function reads the selected file deserializing the messages and creating a new Session
     *
     * @return if the reading has been succesfull
     */
    private boolean readSavedMessages() {
        if (!SAVE_FILE_PATH.isEmpty()) {
            try {
                if (defaultSession == null) {
                    defaultSession = new Session("default");
                    defaultSession.isOffline = true;

                    File f = new File(SAVE_FILE_PATH);
                    Scanner r = new Scanner(f);

                    Gson json = new Gson();
                    while (r.hasNextLine()) {
                        HTTPReqRes tmp = json.fromJson(r.nextLine(), HTTPReqRes.class);
                        defaultSession.messages.add(tmp);
                    }
                } else {
                    System.out.println("main session already created, skipping message reading from file");
                }
                return true;
            } catch (FileNotFoundException fileNotFoundException) {
                fileNotFoundException.printStackTrace();
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Method which executes the entire test suite
     */
    protected void executeSuite() {
        // clears all previously saved tests
        actives.clear();
        passives.clear();
        actual_operation = null;
        ex = null;
        active_ex_finished = false;

        // clears the test suite result table
        DefaultTableModel dm = (DefaultTableModel) resultTable.getModel();
        dm.getDataVector().removeAllElements();
        dm.fireTableDataChanged();

        System.out.println("Number of test found: " + testSuite.getTests().size());
        for (Test t : testSuite.getTests()) {
            if (t.isActive) {
                actives.add(t);
            } else {
                passives.add(t);
            }
        }

        if (OFFLINE) {
            if (!readSavedMessages()) {
                System.err.println("Can't read message file");
                lblOutput.setText("Can't read message file");
                return;
            }
        }//TODO: re-enable OFFLINE mode
        /* else if (passives.size() > 0 && defaultSession == null && actives.size() == 0) {
            lblOutput.setText("Track need to be run for passive tests before executing tests");
            return;
        }
        */

        if (actives.isEmpty()) {
            synchronized (lock2) {
                active_ex_finished = true;
            }
        }

        // Execute active tests
        if (!actives.isEmpty()) {
            try {
                for (String key : session_port.keySet()) {
                    if (session_port.get(key).equals("")) {
                        lblOutput.setText("session port not configured");
                        return;
                    }
                }
                ex = new ExecuteActives(actives, waiting);

                editConfigFile("last_browser_used", btnselectChrome.isEnabled() ? "firefox" : "chrome");

                ex.registerExecuteActivesListener(new ExecuteActiveListener() {
                    @Override
                    public void onExecuteStart() {
                        INTERCEPT_ENABLED = false;
                        actual_operation = new Operation();
                        lblOutput.setText("Executing active tests");
                    }

                    @Override
                    public void onExecuteDone() {
                        if (passives.isEmpty()) {
                            update_gui_test_results();

                            lblOutput.setText("Done. Executed Passive Tests: "
                                    + (passives.isEmpty() ? 0 : passives.size())
                                    + " - Active Tests: "
                                    + (testSuite.getTests().size() - (passives.isEmpty() ? 0 : passives.size())));
                        } else {
                            lblOutput.setText("Executed Active tests, now doing passives");
                        }
                        synchronized (lock2) {
                            active_ex_finished = true;
                        }
                    }


                    @Override
                    public void onNewProcessOperation(Operation op) {
                        INTERCEPT_ENABLED = true;
                        actual_operation = op;
                    }

                    @Override
                    public Operation onOperationDone() {
                        INTERCEPT_ENABLED = false;
                        Operation tmp = actual_operation;

                        actual_operation = new Operation();
                        return tmp;
                    }

                    @Override
                    public Session onNewSession(Session s) {
                        Track track = null;
                        try {
                            track = s.setTrackFromString(getSessionTxt(s.name));
                        } catch (ParsingException e) {
                            lblOutput.setText("error in parsing session track");
                            return null;
                        }
                        String port = session_port.get(s.name);
                        s.port = port;
                        s.track = track;

                        s.ex = new ExecuteTrack(false,
                                !btnselectChrome.isEnabled(),
                                DRIVER_PATH,
                                track,
                                port,
                                s.name);
                        return s;
                    }

                    @Override
                    public void onNewTest(Test actual_test) {
                        actual_operation = null;
                    }

                    public void onTestDone(Test actual_test) {
                        int indx = testSuite.tests.indexOf(actual_test);
                        if (indx != -1) {
                            System.out.printf("Saving test %s in test results", actual_test.getName());
                            testSuite.tests.set(indx, actual_test);
                        }
                    }

                    @Override
                    public void onError(Test actual_test) {
                        System.err.println("Error executing the test:" + actual_test.name);
                        synchronized (lock2) {
                            active_ex_finished = true;
                        }
                    }
                });

                active_ex = new Thread(ex);
                active_ex.start();

            } catch (Exception er) {
                er.printStackTrace();
                System.out.println(er.getLocalizedMessage() + "nad" + er.getMessage() + "2" + er);

                lblOutput.setText("PROBLEM IN Executing Suite, check it please");
            }
        }

        // Execute passive tests
        if (!passives.isEmpty()) {
            // TODO: Add offline clause
            /*
            if (defaultSession.messages.size() == 0) {
                lblOutput.setText("no message found");
                return;
            }
            */

            ExecutePassiveListener listener = new ExecutePassiveListener() {
                @Override
                public boolean onWaitToStart() {
                    // waits for active test execution to finish before doing passives
                    synchronized (lock2) {
                        return active_ex_finished;
                    }
                }

                @Override
                public void onExecuteStart() {
                    lblOutput.setText("Executing passive tests");
                }

                @Override
                public void onExecuteDone(List<Test> passives_test) {
                    //Actives are already executed, because passives are started after actives
                    lblOutput.setText("Done. Executed Passive Tests: "
                            + (passives.isEmpty() ? 0 : passives.size())
                            + " - Active Tests: "
                            + (testSuite.getTests().size() - (passives.isEmpty() ? 0 : passives.size())));

                    passives = passives_test;

                    update_gui_test_results();
                }

                @Override
                public void onError(String msg) {
                    lblOutput.setText(msg);
                }

                @Override
                public Session onNewSession(Session s) throws ParsingException {
                    s.setTrackFromString(getSessionTxt(s.name));

                    String port = session_port.get(s.name);
                    s.port = port;

                    s.ex = new ExecuteTrack(false,
                            !btnselectChrome.isEnabled(),
                            DRIVER_PATH,
                            s.track,
                            port,
                            s.name);

                    return s;
                }

                @Override
                public void onBeforeExecuteTrack() {
                    //Clear previous interceptedMessages if any
                    interceptedMessages.clear();
                    //Tell Burp Extender class to record the intercepted messages from now on
                    recording = true;
                }

                @Override
                public ArrayList<HTTPReqRes> onTrackExecuteDone() {
                    recording = false;
                    return interceptedMessages;
                }
            };

            ExecutePassives expa = new ExecutePassives(
                    passives,
                    listener,
                    messageTypes);

            new Thread(expa).start();
        }
    }

    /**
     * Function used to get the text of the text area of a certain session using the session name
     *
     * @param session_name the name of the session to get the text
     * @return the content of the session tab if it is not empty, otherwise the main session text tab
     */
    private String getSessionTxt(String session_name) {
        if (sessions_text.containsKey(session_name)) {
            JTextArea t = (JTextArea) sessions_text.get(session_name);
            if (t.getText().equals("")) {
                return txtScript.getText();
            } else {
                return t.getText();
            }
        }
        return null;
    }

    /**
     * Update the session config tab, using the session_port variable, at the same time reads if there are changes, and
     * updates the session_port variable
     */
    private void updateTxtSessionConfig() throws ParsingException {
        setSession_configError(false, "");

        String text = txtSessionConfig.getText();
        Pattern p = Pattern.compile("\\n");
        Matcher m = p.matcher(text);
        text = m.replaceAll("");

        if (text.equals("")) {
            String tmp = "";
            for (String s : session_port.keySet()) {
                tmp += s;
                tmp += ":" + session_port.get(s) + ";\n";
            }
            txtSessionConfig.setText(tmp);
            return;
        }

        String[] text_list = text.split(";");

        for (String row : text_list) {
            String[] splitted = row.trim().split(":");
            if (splitted.length == 0) continue;
            if (splitted.length <= 1) {
                String[] splitted2 = new String[]{"", ""};
                splitted2[0] = splitted[0];
                splitted = splitted2;
            }
            String port = splitted[1].trim();
            p = Pattern.compile("^\\d+$");
            m = p.matcher(splitted[1].trim());
            if (!m.find()) {
                setSession_configError(true, "invalid port");

                throw new ParsingException("Invalid port");
            }
            if (session_port.containsKey(splitted[0].trim())) {
                session_port.replace(splitted[0].trim(), splitted[1].trim());
            } else {
                session_port.put((splitted[0]).trim(), splitted[1].trim());
            }
        }
        String tmp = "";
        for (String key : session_port.keySet()) {
            tmp += key + ": " + session_port.get(key) + ";\n";
        }

        txtSessionConfig.setText(tmp);
    }

    /**
     * This function updates the session tabs in the gui to match the actual value in session_names
     */
    private void updateSessionTabs() {
        List<String> present = new ArrayList<>();

        for (int i = 1; i < top_tabbed.getTabCount(); i++) {
            present.add(top_tabbed.getTitleAt(i));
            if (!sessions_names.contains(top_tabbed.getTitleAt(i))) {
                top_tabbed.remove(i);
            }
        }
        for (String name : sessions_names) {
            if (!present.contains(name)) {
                JTextArea tmp = new JTextArea();
                JScrollPane sp = new JScrollPane(tmp,
                        JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                        JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
                sessions_text.put(name, tmp);
                top_tabbed.add(name, sp);
            }
        }
        JTextArea tmp = new JTextArea();
        JScrollPane sp = new JScrollPane(tmp,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
    }

    /**
     * Function used to set the JSON textbox with a red colour to highlight an error.
     *
     * @param isInError true to highlight an error, false to remove the highlight
     * @param msg       the error message to display
     */
    private void setJSONError(boolean isInError, String msg) {
        if (isInError) {
            txtSearch.setBorder(BorderFactory.createLineBorder(Color.RED, 3));
            lblOutput.setText(msg);
            bot_tabbed.setBackgroundAt(bot_tabs_index.get("Input JSON"), Color.RED);
        } else {
            txtSearch.setBorder(BorderFactory.createEmptyBorder());
            lblOutput.setText("");
            bot_tabbed.setBackgroundAt(bot_tabs_index.get("Input JSON"), Color.white);
        }
    }

    /**
     * Function used to set the session config textbox with a red border to highlight an error.
     *
     * @param isInError true to highlight an error, false to remove highlight
     * @param msg       The error message to display
     */
    private void setSession_configError(boolean isInError, String msg) {
        if (isInError) {
            txtSessionConfig.setBorder(BorderFactory.createLineBorder(Color.RED, 3));
            lblOutput.setText(msg);
            bot_tabbed.setBackgroundAt(bot_tabs_index.get("session config"), Color.RED);
        } else {
            txtSessionConfig.setBorder(BorderFactory.createEmptyBorder());
            lblOutput.setText("");
            bot_tabbed.setBackgroundAt(bot_tabs_index.get("session config"), Color.white);
        }
    }

    /**
     * Function used to update the gui test results after the tests are executed
     */
    private void update_gui_test_results() {
        for (Test t : testSuite.getTests()) {
            String esito = "";
            if (t.applicable) {
                esito = t.success ? "passed" : "failed";
            } else {
                esito = "not applicable";
            }
            String[] tmp = new String[]{t.getName(),
                    t.getDescription(),
                    t.references,
                    t.violated_properties,
                    t.affected_entity,
                    t.mitigations,
                    esito};
            System.out.println(t.getName() + " " + esito);
            addItem(tmp);
        }

        testSuite.log_test_suite(LOG_FOLDER);

        btnExecuteSuite.setEnabled(false);
    }

    private void setup_tab_track() {
        lblTrack = new JLabel("Session track ");
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 0, 0, 0);
        gbc.gridx = 0;
        gbc.gridy = 0;
        trackContainer.add(lblTrack, gbc);

        txtScript = new JTextArea();
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(10, 0, 0, 10);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        gbc.gridheight = 4;

        JScrollPane scrollPane1 = new JScrollPane(txtScript,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        top_tabbed = new JTabbedPane();
        top_tabbed.add("main", scrollPane1);
        trackContainer.add(top_tabbed, gbc);
    }

    private void setup_tab_butons() {
        driverSelector = new JFileChooser();
        btndriverSelector = new JButton("Select Driver");

        btndriverSelector.addActionListener(actionEvent -> {
            int returnVal = driverSelector.showOpenDialog(Main.this);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                File file = driverSelector.getSelectedFile();
                DRIVER_PATH = file.getPath();
                if (is_driver_path_valid()) {
                    editConfigFile("last_driver_path", DRIVER_PATH);
                    lbldriver.setText("Driver Selected");
                    btndriverSelector.setBackground(Color.GREEN);
                    btnTestTrack.setEnabled(true);
                } else {
                    lbldriver.setText("Driver:selected executable seems to not work, check logs");
                }
            } else if ((returnVal == JFileChooser.ERROR) || (returnVal == JFileChooser.ERROR_OPTION)) {
                lbldriver.setText("Driver:error during file selection");
                System.out.println("error during file selection");
                btnTestTrack.setEnabled(false);

                btndriverSelector.setBackground(Color.RED);
            } else {
                lbldriver.setText("Driver file still not selected");
                btnTestTrack.setEnabled(false);
                btndriverSelector.setBackground(Color.RED);
            }
        });

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 10);
        gbc.gridx = 4;
        gbc.gridy = 1;
        trackContainer.add(btndriverSelector, gbc);

        lbldriver = new JLabel("Driver file still not selected");
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.SOUTHEAST;
        gbc.insets = new Insets(10, 0, 0, 30);
        gbc.gridx = 3;
        gbc.gridy = 0;
        trackContainer.add(lbldriver, gbc);

        btnTestTrack = new JButton("Test track");
        btnTestTrack.setEnabled(true);

        btnTestTrack.addActionListener(e -> {
            ExecuteTrackListener listener = new ExecuteTrackListener() {
                @Override
                public void onExecuteDone(boolean errors, String current_url, String sessionName) {
                    if (errors) {
                        lblOutput.setText("Error in executing track");
                    } else {
                        lblOutput.setText("Track Executed correctly");
                    }
                }

                @Override
                public void onExecuteDone(boolean forceResult, String sessionName) {
                    if (forceResult) {
                        lblOutput.setText("Track Executed correctly");
                    } else {
                        lblOutput.setText("Error in executing track");
                    }
                }

                @Override
                public void onError(String sessionName) {
                    lblOutput.setText("Error in executing track");
                }

                @Override
                public Boolean onAskPause(String sessionName) {
                    return false;
                }

                @Override
                public Boolean onAskStop(String sessionName) {
                    return false;
                }

                @Override
                public Boolean onAskClearCookie(String sessionName) {
                    return null;
                }

                @Override
                public void onNextSessionAction(SessionTrackAction last_action,
                                                SessionTrackAction last_open,
                                                SessionTrackAction last_click,
                                                String last_url,
                                                String session_name) {

                }

                @Override
                public Track onUpdateTrack(String sessionName) throws ParsingException {
                    return null;
                }

                @Override
                public void onSetVar(Var v) {
                }
            };
            recording = false;
            defaultSession = new Session("temp");

            Track track = null;
            try {
                track = defaultSession.setTrackFromString(txtScript.getText());
            } catch (ParsingException exc) {
                lblOutput.setText("Error in parsing session track");
            }

            defaultSession = null;
            ExecuteTrack ex = new ExecuteTrack(false,
                    !btnselectChrome.isEnabled(),
                    DRIVER_PATH,
                    track,
                    DEFAULT_PORT.toString(),
                    "test");
            ex.registerExecuteTrackListener(listener);
            new Thread(ex).start();
        });

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 5;
        gbc.gridy = 1;
        btnTestTrack.setPreferredSize(new Dimension(100, 20));
        trackContainer.add(btnTestTrack, gbc);

        btnselectChrome = new JButton("Use Chrome");
        btnselectChrome.setEnabled(false);
        btnselectChrome.addActionListener(actionEvent -> {
            btnTestTrack.setEnabled(false);
            lbldriver.setText("Driver file still not selected");
            btndriverSelector.setBackground(Color.RED);

            btnselectChrome.setEnabled(false);
            btnselectFirefox.setEnabled(true);
            lblnextTestBrowser.setText("Chrome");
        });

        lblnextTestBrowser = new JLabel("Firefox");
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 4;
        gbc.gridy = 2;
        trackContainer.add(btnselectChrome, gbc);

        btnselectFirefox = new JButton("Use Firefox");
        btnselectFirefox.setEnabled(true);
        btnselectFirefox.addActionListener(actionEvent -> {
            btnTestTrack.setEnabled(false);
            lbldriver.setText("Driver file still not selected");
            btndriverSelector.setBackground(Color.RED);

            btnselectFirefox.setEnabled(false);
            btnselectChrome.setEnabled(true);
            lblnextTestBrowser.setText("Firefox");
        });

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 4;
        gbc.gridy = 3;
        btnselectFirefox.setPreferredSize(new Dimension(100, 20));
        trackContainer.add(btnselectFirefox, gbc);

        JFileChooser messageSaver = new JFileChooser();
        btnSetRecording = new JButton("Record");
        btnSetRecording.setEnabled(true);

        // Recording button listener
        btnSetRecording.addActionListener(actionEvent -> {
            if (btnSetRecording.isEnabled()) {
                int returnVal = messageSaver.showOpenDialog(Main.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = messageSaver.getSelectedFile();
                    RECORD_FILE_PATH = file.getPath();
                    lblOutput.setText("File selected");

                    SAVE_TO_FILE = true;

                    defaultSession = new Session("default");
                    try {
                        defaultSession.setTrackFromString(txtScript.getText());
                    } catch (ParsingException e) {
                        lblOutput.setText("Error in parsing session track");
                        return;
                    }

                    btnSetRecording.setBackground(new Color(255, 0, 0));
                    btnSetRecording.setText("recording..");

                    recording = true;

                    ExecuteTrackListener listener = new ExecuteTrackListener() {
                        @Override
                        public void onExecuteDone(boolean errors, String current_url, String sessionName) {
                            recording = false;

                            if (errors) {
                                lblOutput.setText("Errore nell'esecuzione della traccia");
                            }

                            lblOutput.setText("Track recorded");

                            if (SAVE_TO_FILE) {
                                FileWriter w;
                                try {
                                    w = new FileWriter(RECORD_FILE_PATH);

                                    for (HTTPReqRes actual : defaultSession.messages) {
                                        Gson geson = new Gson();
                                        String serialized = geson.toJson(actual);
                                        w.write(serialized + "\n");
                                    }
                                    w.close();
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }
                            }
                            btnSetRecording.setBackground(Color.white);
                            btnSetRecording.setText("record");
                        }

                        @Override
                        public void onExecuteDone(boolean forceResult, String sessionName) {

                        }

                        @Override
                        public void onError(String sessionName) {
                            lblOutput.setText("Errore nell'esecuzione della traccia");
                        }

                        @Override
                        public Boolean onAskPause(String sessionName) {
                            return false;
                        }

                        @Override
                        public Boolean onAskStop(String sessionName) {
                            return false;
                        }

                        @Override
                        public Boolean onAskClearCookie(String sessionName) {
                            return false;
                        }

                        @Override
                        public void onNextSessionAction(SessionTrackAction last_action,
                                                        SessionTrackAction last_open,
                                                        SessionTrackAction last_click,
                                                        String last_url,
                                                        String session_name) {

                        }

                        @Override
                        public Track onUpdateTrack(String sessionName) throws ParsingException {
                            return null;
                        }

                        @Override
                        public void onSetVar(Var v) {
                        }
                    };

                    ExecuteTrack ex = new ExecuteTrack(false,
                            !btnselectChrome.isEnabled(),
                            DRIVER_PATH,
                            defaultSession.track,
                            defaultSession.port,
                            "main");
                    ex.registerExecuteTrackListener(listener);
                    new Thread(ex).start();

                } else if ((returnVal == JFileChooser.ERROR) || (returnVal == JFileChooser.ERROR_OPTION)) {
                    lblOutput.setText("error in selecting output file");
                    System.out.println("error in selecting output file");
                } else {
                    lbldriver.setText("Messages still not loaded");
                }
            }
        });

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 5;
        gbc.gridy = 2;
        btnSetRecording.setPreferredSize(new Dimension(100, 20));
        trackContainer.add(btnSetRecording, gbc);

        // Button Execute track
        btnExecuteTrack = new JButton("execute track");
        btnExecuteTrack.addActionListener(actionEvent -> {
            defaultSession = new Session("default");
            try {
                defaultSession.setTrackFromString(txtScript.getText());
            } catch (ParsingException e) {
                lblOutput.setText("Error in parsing session track");
                return;
            }
            btnExecuteTrack.setText("executing..");
            interceptedMessages.clear();
            recording = true;

            ExecuteTrackListener listener = new ExecuteTrackListener() {
                @Override
                public void onExecuteDone(boolean errors, String current_url, String sessionName) {
                    recording = false;

                    if (errors) {
                        lblOutput.setText("Errore nell'esecuzione della traccia");
                    }

                    lblOutput.setText("Track executed");

                    btnExecuteTrack.setText("execute track");
                }

                @Override
                public void onExecuteDone(boolean forceResult, String sessionName) {

                }

                @Override
                public void onError(String sessionName) {
                    lblOutput.setText("Errore nell'esecuzione della traccia");
                }

                @Override
                public Boolean onAskPause(String sessionName) {
                    return false;
                }

                @Override
                public Boolean onAskStop(String sessionName) {
                    return false;
                }

                @Override
                public Boolean onAskClearCookie(String sessionName) {
                    return null;
                }

                @Override
                public void onNextSessionAction(SessionTrackAction last_action,
                                                SessionTrackAction last_open,
                                                SessionTrackAction last_click,
                                                String last_url,
                                                String session_name) {
                }

                @Override
                public Track onUpdateTrack(String sessionName) throws ParsingException {
                    return null;
                }

                @Override
                public void onSetVar(Var v) {
                }
            };

            editConfigFile("last_browser_used", btnselectChrome.isEnabled() ? "firefox" : "chrome");

            ExecuteTrack ex = new ExecuteTrack(false,
                    !btnselectChrome.isEnabled(),
                    DRIVER_PATH,
                    defaultSession.track,
                    defaultSession.port,
                    "main");
            ex.registerExecuteTrackListener(listener);
            new Thread(ex).start();
        });

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 5;
        gbc.gridy = 3;
        btnSetRecording.setPreferredSize(new Dimension(100, 20));
        trackContainer.add(btnExecuteTrack, gbc);

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 4;
        gbc.gridy = 4;
        trackContainer.add(new JLabel("Next test will use"), gbc);

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(20, 0, 0, 0);
        gbc.gridx = 4;
        gbc.gridy = 4;
        trackContainer.add(lblnextTestBrowser, gbc);

        JFileChooser messageLoader = new JFileChooser();
        btnLoadMessages = new JButton("load messages");
        btnLoadMessages.setEnabled(true);
        btnLoadMessages.addActionListener(actionEvent -> {
            if (btnLoadMessages.getBackground() == Color.GREEN) {
                btnSetOffline.setEnabled(false);
                btnSetOffline.setBackground(Color.white);
                btnLoadMessages.setBackground(Color.white);
                btnLoadMessages.setText("load messages");
                OFFLINE = false;
                SAVE_FILE_PATH = "";

            } else {
                int returnVal = messageLoader.showOpenDialog(Main.this);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    File file = messageLoader.getSelectedFile();
                    SAVE_FILE_PATH = file.getPath();
                    lblOutput.setText("Messages selected");
                    btnLoadMessages.setBackground(Color.GREEN);
                    btnLoadMessages.setText("unload");
                    btnSetOffline.setEnabled(true);
                } else if ((returnVal == JFileChooser.ERROR) || (returnVal == JFileChooser.ERROR_OPTION)) {
                    lblOutput.setText("error in selecting messages");
                    System.out.println("error in selecting messages");
                    btnSetOffline.setEnabled(false);
                    btnLoadMessages.setBackground(Color.RED);
                } else {
                    lbldriver.setText("Messages still not loaded");
                    btnSetOffline.setEnabled(false);
                    btnLoadMessages.setBackground(Color.RED);
                }
            }
        });

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 6;
        gbc.gridy = 1;
        trackContainer.add(btnLoadMessages, gbc);

        btnSetOffline = new JButton("offline mode");
        btnSetOffline.setEnabled(false);
        btnSetOffline.addActionListener(actionEvent -> {
            if (btnSetOffline.getBackground() == Color.green) {
                OFFLINE = false;
                btnSetOffline.setBackground(Color.white);
            } else {
                btnSetOffline.setBackground(Color.green);
                OFFLINE = true;
            }
        });
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 6;
        gbc.gridy = 2;
        trackContainer.add(btnSetOffline, gbc);

        btnSaveToFile = new JButton("save");
        btnSaveToFile.addActionListener(actionEvent -> {
            if (SAVE_TO_FILE) {
                FileWriter w;
                try {
                    w = new FileWriter(RECORD_FILE_PATH);

                    for (HTTPReqRes actual : defaultSession.messages) {
                        Gson geson = new Gson();
                        String serialized = geson.toJson(actual);
                        w.write(serialized + "\n");
                    }
                    w.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridx = 6;
        gbc.gridy = 3;
        trackContainer.add(btnSaveToFile, gbc);
    }

    private JPanel setup_tab_input_json(GridBagLayout bottom_layout) {
        inputContainer = new JPanel();
        inputContainer.setLayout(bottom_layout);

        lblInfo = new JLabel(" ");
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        inputContainer.add(lblInfo, gbc);

        lblOutput = new JLabel(" ");
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 0;
        gbc.gridy = 4;
        gbc.gridwidth = 2;
        inputContainer.add(lblOutput, gbc);

        txtSearch = new JTextArea();

        JScrollPane scrollPane2 = new JScrollPane(txtSearch,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.gridheight = 3;
        inputContainer.add(scrollPane2, gbc);

        btnReadJSON = new JButton("Read JSON");
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 2;
        gbc.gridy = 2;
        inputContainer.add(btnReadJSON, gbc);

        btnReadJSON.addActionListener(e -> {
            testSuite = new TestSuite();

            readMsgDefFile(); // Updates the Message Definitions
            readJSONinput(txtSearch.getText());

            try {
                updateTxtSessionConfig();
            } catch (ParsingException exc) {
                setJSONError(true, "error in updating the session config");
            }

            lblOutput.setText("Number of Tests: " + testSuite.getTests().size());

            if (testSuite.getTests().size() > 0) {
                btnExecuteSuite.setEnabled(true);
            }
        });

        JButton btnStop = new JButton("Stop");
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 2;
        gbc.gridy = 1;
        inputContainer.add(btnStop, gbc);

        btnStop.addActionListener(e -> {
            if (active_ex != null) {
                active_ex.interrupt();
                INTERCEPT_ENABLED = false;
                active_ex.stop();
            }
        });

        btnExecuteSuite = new JButton("Execute Test Suite");
        btnExecuteSuite.setEnabled(false);


        btnExecuteSuite.addActionListener(e -> {
            executeSuite();
        });

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.SOUTHWEST;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 2;
        gbc.gridy = 3;
        inputContainer.add(btnExecuteSuite, gbc);
        return inputContainer;
    }

    private JScrollPane setup_tab_suite_result(GridBagLayout bottom_layout) {
        resultTableModel = new DefaultTableModel(foundData, testSuiteColNames) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        resultTable = new JTable(resultTableModel) {
            //Implement table cell tool tips.
            public String getToolTipText(MouseEvent e) {
                String tip = null;
                java.awt.Point p = e.getPoint();
                int rowIndex = rowAtPoint(p);
                int colIndex = columnAtPoint(p);

                try {
                    tip = getValueAt(rowIndex, colIndex).toString();
                } catch (RuntimeException e1) {
                    //catch null pointer exception if mouse is over an empty line
                }
                return tip;
            }
        };

        resultTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table,
                                                           Object value,
                                                           boolean isSelected,
                                                           boolean hasFocus,
                                                           int row,
                                                           int column) {
                final Component c = super.getTableCellRendererComponent(table,
                        value,
                        isSelected,
                        hasFocus,
                        row,
                        column);
                if (value == null) return c;
                if (value.equals("failed")) {
                    c.setBackground(Color.RED);
                } else {
                    c.setBackground(null);
                }
                return c;
            }
        });

        JScrollPane scrollPane = new JScrollPane(resultTable,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Adds all the test result to the result table
        resultTable.getSelectionModel().addListSelectionListener(event -> {
            if (resultTable.getSelectedRow() > -1) {

                int row = resultTable.getSelectedRow();
                //BurpSuite.getTests.get(row).getTable();

                DefaultTableModel dm = (DefaultTableModel) testTable.getModel();
                dm.getDataVector().removeAllElements();
                dm.fireTableDataChanged();

                for (String[] act : testSuite.getTests().get(row).getRows()) {

                    ((DefaultTableModel) testTable.getModel()).addRow(act);
                }
            }
        });
        return scrollPane;
    }

    private JSplitPane setup_tab_test_result(GridBagLayout bottom_layout) {
        // Test Result Tab
        testTableModel = new DefaultTableModel(foundData, foundTableColNames) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        testTable = new JTable(testTableModel);
        // Add all the operations result to the table
        testTable.getSelectionModel().addListSelectionListener(listSelectionEvent -> {
            if (!listSelectionEvent.getValueIsAdjusting()) {
                if (testTable.getSelectedRow() == -1) return;
                int index = Integer.parseInt((String) testTable.getModel().getValueAt(testTable.getSelectedRow(), 4));
                int op_index = Integer.parseInt((String) testTable.getModel().getValueAt(testTable.getSelectedRow(), 0));

                Operation op = testSuite.tests.get(resultTable.getSelectedRow()).operations.get(op_index);

                MessageType msg_type;
                try {
                    msg_type = MessageType.getFromList(messageTypes, op.getMessageType());
                } catch (ParsingException e) {
                    throw new RuntimeException(e);
                }

                for (HTTPReqRes m : op.matchedMessages) {
                    if (m.index == index) {
                        if (msg_type.msg_to_process_is_request) {
                            messageViewer.setMessage(m.getRequest(), true);
                        } else {
                            messageViewer.setMessage(m.getResponse(), false);
                        }
                        break;
                    }
                }
            }
        });

        JScrollPane scrollPane3 = new JScrollPane(testTable,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        splitPane.setLeftComponent(scrollPane3);

        controller = new IMessageEditorController() {
            @Override
            public IHttpService getHttpService() {
                return new IHttpService() {
                    @Override
                    public String getHost() {
                        return null;
                    }

                    @Override
                    public int getPort() {
                        return 0;
                    }

                    @Override
                    public String getProtocol() {
                        return null;
                    }
                };
            }

            @Override
            public byte[] getRequest() {
                return viewedMessage.getRequest();
            }

            @Override
            public byte[] getResponse() {
                return viewedMessage.getResponse();
            }
        };
        return splitPane;
    }

    private JPanel setup_tab_session_config(GridBagLayout bottom_layout) {
        JPanel sessionConfig = new JPanel();
        sessionConfig.setLayout(bottom_layout);

        txtSessionConfig = new JTextArea();
        JScrollPane scrollPane5 = new JScrollPane(txtSessionConfig, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.gridheight = 3;
        sessionConfig.add(scrollPane5, gbc);

        JButton btnSetSessionConfig = new JButton("save");
        btnSetSessionConfig.addActionListener(actionEvent -> {
            try {
                updateTxtSessionConfig();
            } catch (ParsingException e) {
                e.printStackTrace();
            }
        });

        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 2;
        gbc.gridy = 3;
        gbc.gridwidth = 1;
        gbc.gridheight = 1;
        sessionConfig.add(btnSetSessionConfig, gbc);

        return sessionConfig;
    }

    private JPanel setub_tab_debug(GridBagLayout bottom_layout) {
        // Debug Tab
        JPanel debugPanel = new JPanel();

        debugPanel.setLayout(bottom_layout);

        txt_out_debug_tab.setEditable(false);
        JScrollPane scrollPane6 = new JScrollPane(txt_out_debug_tab,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        GridBagConstraints constraints1 = new GridBagConstraints();
        constraints1.gridx = 0;
        constraints1.gridy = 1;
        constraints1.gridwidth = 1; // One cell wide
        constraints1.gridheight = 3; // One cell high
        constraints1.fill = GridBagConstraints.BOTH;
        constraints1.weightx = 0.5; // Half of the horizontal space
        constraints1.weighty = 0.5; // Half of the vertical space
        debugPanel.add(scrollPane6, constraints1);

        txt_err_debug_tab.setEditable(false);
        JScrollPane scrollPane7 = new JScrollPane(txt_err_debug_tab,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        GridBagConstraints constraints2 = new GridBagConstraints();
        constraints2.gridx = 1;
        constraints2.gridy = 1;
        constraints2.gridwidth = 1; // One cell wide
        constraints2.gridheight = 3; // One cell high
        constraints2.fill = GridBagConstraints.BOTH;
        constraints2.weightx = 0.5; // Half of the horizontal space
        constraints2.weighty = 0.5; // Half of the vertical space
        debugPanel.add(scrollPane7, constraints2);

        JButton btn_clear = new JButton("clear");
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 2;
        gbc.gridy = 1;
        debugPanel.add(btn_clear, gbc);

        btn_clear.addActionListener(e -> {
            txt_out_debug_tab.setText("");
            txt_err_debug_tab.setText("");
        });

        JLabel lbl_left = new JLabel("Output log");
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        debugPanel.add(lbl_left, gbc);

        JLabel lbl_right = new JLabel("Error log");
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(10, 10, 10, 10);
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        debugPanel.add(lbl_right, gbc);

        return debugPanel;
    }
}