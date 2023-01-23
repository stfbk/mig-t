# tool quickstart guide
I suggest you to download the lastest release of the tool from the release page, otherwise you can compile the last version from the source code by following the steps described in the README.md in the root folder.

## Download & start the tool

1. download from the release page the last version of the tool select the one which ends with `with-dependencies`, or compile the source code.
2. Download the last version of [Burp Suite Community Edition](https://portswigger.net/burp/releases/community/latest)
3. Start Burp and go in the *Exstensions* tab
4. Press *Add* button
5. In the *Extension file (.jar)* select the tool jar you downloaded before
6. Now the plugin should be loaded, go to the "Plugin Draft" tab

## Download and add browser driver
Depending on the browser you want to use (firefox or chrome), you will need to specify the corresponding driver. Note that you have to download the driver for the corresponding browser version

To download the driver go to:
- [Driver for chrome](https://chromedriver.chromium.org/home)
- [Driver for firefox](https://github.com/mozilla/geckodriver/releases)

Select the browser you want to use using the buttons in the tool interface.

To add the driver to the tool, use the "select driver" button in the tool interface and locate the driver file you downloaded before.

## Run a test
