package org.zaproxy.addon.migt;

import java.io.File;
import java.time.Duration;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.NoSuchWindowException;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.SessionNotCreatedException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * Class that executes a Session Track (series of user actions). It launches a browser with Selenium
 * to automate the actions
 */
public class ExecuteTrack implements Runnable {
    private static String snapshot = "";
    private final boolean chrome_selected;
    private final String driver_path;
    private final boolean isHeadless;
    private final Track track;
    public String current_url;
    public String port = "";
    public String sessionName;
    public boolean isInPause;
    public ExecuteTrackListener listener;
    private Boolean isReqClearCookies = false;

    /**
     * Instantiate the ExecuteTrack Object
     *
     * @param isHeadless
     * @param chrome_selected tells if chrome is selected as a browser to be used, otherwise firefox
     *     is used
     * @param driver_path the path to the chosen browser's driver
     * @param track the track to be executed
     * @param port the port set in the browser that the HTTP(S) proxy is listening to
     * @param sessionName The name of the session to be executed
     */
    public ExecuteTrack(
            boolean isHeadless,
            boolean chrome_selected,
            String driver_path,
            Track track,
            String port,
            String sessionName) {
        this.chrome_selected = chrome_selected;
        this.driver_path = driver_path;
        this.track = track; // TODO: can't I just take the session object?
        this.isHeadless = isHeadless;
        this.port = port;
        this.sessionName = sessionName; // TODO: can't I just take the session object?
    }

    /**
     * Registers the execute track listener, used to communicate with the ExecuteTrack thread
     *
     * @param listener the listener
     */
    public void registerExecuteTrackListener(ExecuteTrackListener listener) {
        this.listener = listener;
    }

    /** Runs the session track */
    @Override
    public void run() {
        WebDriver driver;
        int TIMEOUT = 10;

        if (chrome_selected) {
            ChromeOptions options = new ChromeOptions();
            options.addArguments("ignore-certificate-errors");
            options.addArguments("window-size=1280,1400");
            options.addArguments("--proxy-bypass-list=<-loopback>");
            options.addArguments("--remote-allow-origins=*");
            Proxy proxy = new Proxy();
            proxy.setHttpProxy("localhost:" + port);
            proxy.setSslProxy("localhost:" + port);
            options.setCapability(CapabilityType.PROXY, proxy);
            // options.setHeadless(isHeadless);

            System.setProperty("webdriver.chrome.driver", driver_path);
            try {
                driver = new ChromeDriver(options);
            } catch (SessionNotCreatedException e) {
                e.printStackTrace();
                return;
            }

        } else {
            FirefoxOptions options = new FirefoxOptions();
            options.addArguments("-width=1280");
            options.addArguments("-height=1400");
            Proxy proxy = new Proxy();
            proxy.setHttpProxy("localhost:" + port);
            proxy.setSslProxy("localhost:" + port);
            options.setCapability(CapabilityType.PROXY, proxy);
            // options.setHeadless(isHeadless);

            System.setProperty("webdriver.gecko.driver", driver_path);
            try {
                driver = new FirefoxDriver(options);
            } catch (SessionNotCreatedException e) {
                e.printStackTrace();
                return;
            }
        }

        WebElement currentElement = null;
        int act_window_index = 0;

        SessionTrackAction last_action = null;
        SessionTrackAction last_open = null;
        SessionTrackAction last_click = null;
        String last_url = "";

        int startindex = 0;

        beforeloop:
        try {
            for (int i = startindex; i < track.getTrack().size(); i++) {
                last_action = track.getTrack().get(i);

                try {
                    last_url = driver.getCurrentUrl();
                } catch (WebDriverException e) {
                }

                if (track.getTrack().get(i).action == SessionOperation.SessAction.CLICK) {
                    last_click = track.getTrack().get(i);
                }
                if (track.getTrack().get(i).action == SessionOperation.SessAction.OPEN) {
                    last_open = track.getTrack().get(i);
                }
                listener.onNextSessionAction(
                        last_action, last_open, last_click, last_url, sessionName);

                isInPause = listener.onAskPause(sessionName);

                while (isInPause) {
                    isInPause = listener.onAskPause(sessionName);
                    Thread.sleep(1000);
                }

                Thread.sleep(1000); // Don't delete, it is useful

                SessionTrackAction action = track.getTrack().get(i);

                currentElement = null;

                Object[] tmp = driver.getWindowHandles().toArray();
                String[] windows = new String[tmp.length];
                int j = 0;
                for (Object o : tmp) {
                    String act = (String) o;
                    windows[j++] = act;
                }

                int windows_count = windows.length;
                int windows_checked = 0;

                try {
                    driver.getWindowHandle();
                } catch (NoSuchWindowException e) {
                    act_window_index = 0;
                    driver.switchTo().window(windows[act_window_index]);
                }

                switch (action.action) {
                    case WAIT:
                        {
                            String time = action.elem;
                            int time_int = Integer.parseInt(time);

                            Thread.sleep(time_int);
                            continue;
                        }
                    case ALERT:
                        {
                            if (action.elem != null) {
                                Alert alert = null;
                                int c = 0;
                                while (c++ < 10) {
                                    try {
                                        alert = driver.switchTo().alert();
                                        break;
                                    } catch (NoAlertPresentException e) {
                                        Thread.sleep(1000);
                                        continue;
                                    }
                                }
                                if (action.elem.equals("accept")) {
                                    alert.accept();
                                } else if (action.elem.equals("dimiss")) {
                                    alert.dismiss();
                                }
                            } else {
                                throw new ParsingException("invalid alert action");
                            }
                            continue;
                        }
                    case CLEAR_COOKIES:
                        {
                            driver.manage().deleteAllCookies();
                            continue;
                        }
                    case OPEN:
                        {
                            driver.get(action.elem);
                            continue;
                        }
                    case SET_VAR:
                        {
                            Var v = new Var(action.elem, action.content);
                            listener.onSetVar(v);
                            continue;
                        }
                    case TYPE:
                    case CLICK:
                    case SNAPSHOT:
                    case DIFF:
                    case EQUALS:
                    case ASSERT_NOT_VISIBLE:
                    case ASSERT_NOT_CLICKABLE:
                    case ASSERT_CLICKABLE:
                    case ASSERT_VISIBLE:
                    case ASSERT_ELEM_CONTENT_HAS:
                    case ASSERT_ELEM_CONTENT_IS:
                    case ASSERT_ELEM_CLASS_HAS:
                    case ASSERT_ELEM_CLASS_IS:
                    case ASSERT_ELEM_HAS_ATTRIBUTE:
                    case ASSERT_ELEM_NOT_HAS_ATTRIBUTE:
                        {
                            String searchBy = action.elem_type;
                            String identifier = action.elem_source;

                            while (windows_checked != windows_count) {
                                try {
                                    boolean is_snapshot =
                                            action.action == SessionOperation.SessAction.SNAPSHOT
                                                    || action.action
                                                            == SessionOperation.SessAction.DIFF
                                                    || action.action
                                                            == SessionOperation.SessAction.EQUALS;

                                    By by = null;
                                    // Checks for the presence of a valid item to search
                                    switch (searchBy.trim()) {
                                        case "id":
                                            by = By.id(identifier.trim());
                                            break;
                                        case "xpath":
                                            by = By.xpath(identifier.trim());
                                            break;
                                        case "link":
                                            by = By.linkText(identifier.trim());
                                            break;
                                        case "name":
                                            by = By.name(identifier.trim());
                                            break;
                                        case "class":
                                            by = By.className(identifier.trim());
                                            break;
                                        default:
                                            throw new ParsingException(
                                                    "invalid session track command");
                                    }

                                    if (action.action
                                            == SessionOperation.SessAction.ASSERT_VISIBLE) {
                                        new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT))
                                                .until(
                                                        ExpectedConditions
                                                                .visibilityOfElementLocated(by));
                                    } else if (is_snapshot) {
                                        new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT))
                                                .until(
                                                        ExpectedConditions.presenceOfElementLocated(
                                                                by));
                                    } else {
                                        new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT))
                                                .until(ExpectedConditions.elementToBeClickable(by));
                                    }

                                    currentElement = driver.findElement(by);

                                } catch (TimeoutException | NoSuchWindowException e) {
                                    if (act_window_index < windows_count - 1) {
                                        driver.switchTo().window(windows[++act_window_index]);
                                    } else {
                                        act_window_index = 0;
                                        driver.switchTo().window(windows[act_window_index]);
                                    }
                                    windows_checked++;
                                } catch (UnhandledAlertException ex) {
                                    Alert alert = driver.switchTo().alert();
                                    if (alert != null) alert.accept();
                                }
                                if (currentElement != null) break;
                            }
                            if (currentElement == null) {
                                if (action.action == SessionOperation.SessAction.ASSERT_CLICKABLE
                                        || action.action
                                                == SessionOperation.SessAction.ASSERT_VISIBLE) {
                                    listener.onExecuteDone(false, sessionName);
                                    driver.close();
                                    return;
                                }
                                throw new TimeoutException(
                                        identifier.trim() + " Could not be focused");
                            }
                            break;
                        }

                    default:
                        {
                            System.err.printf("error in session %s track", sessionName);
                            throw new ParsingException("invalid session track command" + action);
                        }
                }

                if (currentElement != null) {
                    switch (action.action) {
                        case CLICK:
                            new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT))
                                    .until(ExpectedConditions.elementToBeClickable(currentElement))
                                    .click();
                            break;
                        case TYPE:
                            new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT))
                                    .until(ExpectedConditions.elementToBeClickable(currentElement))
                                    .sendKeys(action.content);
                            break;
                        case SNAPSHOT:
                            new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT))
                                    .until(ExpectedConditions.visibilityOf(currentElement));
                            File f = currentElement.getScreenshotAs(OutputType.FILE);
                            snapshot = currentElement.getScreenshotAs(OutputType.BASE64);
                            f.renameTo(new File("./snapshot.png"));
                            break;
                        case DIFF:
                        case EQUALS:
                            new WebDriverWait(driver, Duration.ofSeconds(TIMEOUT))
                                    .until(ExpectedConditions.visibilityOf(currentElement));
                            String diff = currentElement.getScreenshotAs(OutputType.BASE64);
                            File f2 = currentElement.getScreenshotAs(OutputType.FILE);
                            f2.renameTo(new File("./diff.png"));
                            if (action.action == SessionOperation.SessAction.DIFF) {
                                if (diff.equals(snapshot)) {
                                    listener.onExecuteDone(true, current_url, sessionName);
                                    driver.close();
                                    return;
                                }
                            } else {
                                if (!diff.equals(snapshot)) {
                                    listener.onExecuteDone(true, current_url, sessionName);
                                    driver.close();
                                    return;
                                }
                            }
                            break;
                        case ASSERT_VISIBLE:
                        case ASSERT_CLICKABLE:
                            listener.onExecuteDone(true, sessionName);
                            driver.close();
                            return;
                        case ASSERT_NOT_CLICKABLE:
                        case ASSERT_NOT_VISIBLE:
                            listener.onExecuteDone(false, sessionName);
                            driver.close();
                            return;
                        case ASSERT_ELEM_CONTENT_IS:
                            {
                                String content = currentElement.getText();
                                if (!content.equals(action.content)) {
                                    listener.onExecuteDone(false, sessionName);
                                    driver.close();
                                    return;
                                }
                                break;
                            }
                        case ASSERT_ELEM_CONTENT_HAS:
                            {
                                String content = currentElement.getText();
                                if (!content.contains(action.content)) {
                                    listener.onExecuteDone(false, sessionName);
                                    driver.close();
                                    return;
                                }
                                break;
                            }
                        case ASSERT_ELEM_CLASS_IS:
                            {
                                String classtxt = currentElement.getAttribute("class");
                                if (!classtxt.equals(action.content)) {
                                    listener.onExecuteDone(false, sessionName);
                                    driver.close();
                                    return;
                                }
                                break;
                            }
                        case ASSERT_ELEM_CLASS_HAS:
                            {
                                String classtxt = currentElement.getAttribute("class");
                                if (!classtxt.contains(action.content)) {
                                    listener.onExecuteDone(false, sessionName);
                                    driver.close();
                                    return;
                                }
                                break;
                            }
                        case ASSERT_ELEM_HAS_ATTRIBUTE:
                            {
                                String attr = currentElement.getAttribute(action.content);
                                if (attr == null) {
                                    listener.onExecuteDone(false, sessionName);
                                    driver.close();
                                    return;
                                }
                                break;
                            }
                        case ASSERT_ELEM_NOT_HAS_ATTRIBUTE:
                            {
                                String attr = currentElement.getAttribute(action.content);
                                if (attr != null) {
                                    listener.onExecuteDone(false, sessionName);
                                    driver.close();
                                    return;
                                }
                                break;
                            }
                    }
                }

                listener.onNextSessionAction(
                        last_action, last_open, last_click, last_url, sessionName);

                isReqClearCookies = listener.onAskClearCookie(sessionName);
                if (isReqClearCookies != null) {
                    if (isReqClearCookies) {
                        driver.manage().deleteAllCookies();

                        isReqClearCookies = false;
                    }
                }

                Track new_track = listener.onUpdateTrack(sessionName);

                if (new_track != null && !new_track.equals(track)) {
                    SessionTrackAction last = track.getTrack().get(i);
                    int last_index = new_track.getTrack().lastIndexOf(last);
                    if (last_index == -1) {
                        throw new ParsingException("Error in resuming the track after edit");
                    }
                    startindex = new_track.getTrack().indexOf(last) + 1;
                    break beforeloop;
                }
            }
        } catch (InterruptedException interruptedException) {
            System.out.printf("Session %s stopped, no checks necessary", sessionName);
        } catch (ParsingException | NumberFormatException | ArrayIndexOutOfBoundsException e) {
            System.err.println(e.getMessage());
            current_url = "";
            listener.onError(sessionName);
            driver.close();
            return;
        } catch (TimeoutException e) {
            System.err.println(e.getMessage());
            current_url = "";
            listener.onExecuteDone(true, current_url, sessionName);
            driver.close();
            return;
        } catch (WebDriverException error) {
            current_url = "";
            System.out.printf("ERROR SELENIUM WEBDRIVER (session %s) =>\n %s", sessionName, error);
            listener.onExecuteDone(true, current_url, sessionName);
            driver.close();
            return;
        }
        current_url = "";
        driver.close();
        listener.onExecuteDone(false, current_url, sessionName);
    }
}
