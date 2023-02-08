# MIG-T Pentesting Tool
MIG-T Pentesting Tool is a plugin for BurpSuite that helps security testers automate their testing activities. It allows the tester to define automations to edit or check correctnees of HTTP messages. It integrates an automated browser used to simulate user actions on a webpage, to trigger specific messages. It uses MIG-L language to define tests to be executed by MIG-T<br>

## Quickstart
<details>
  <summary>Details</summary>
I suggest you to download the lastest release of the tool from the release page, otherwise you can compile the last version from the source code by following the steps described in the "how to compile the plugin" section.

## Download & start the tool

1. download from the release page the last version of the tool select the one which ends with `with-dependencies`, or compile the source code.
2. Download the last version of [Burp Suite Community Edition](https://portswigger.net/burp/releases/community/latest)
3. Start Burp and go in the *Exstensions* tab
4. Press *Add* button
5. In the *Extension file (.jar)* select the tool jar you downloaded before
6. Now the plugin should be loaded, go to the "MIG-T" tab

## Download and add browser driver
Depending on the browser you want to use (firefox or chrome), you will need to specify the corresponding driver. Note that you have to download the driver for the corresponding browser version

To download the driver go to:
- [Driver for chrome](https://chromedriver.chromium.org/home)
- [Driver for firefox](https://github.com/mozilla/geckodriver/releases)

Select the browser you want to use using the buttons in the tool interface.

To add the driver to the tool, use the "select driver" button in the tool interface and locate the driver file you downloaded before.

## Run a test

Before starting, make sure you have updated your msg_def.json file in the Burp installation folder. You have to add the definitions of the message_types that you use in your tests in that file.

To run a test you need to fill the "Input JSON" page with the test suite, and click on the "Read JSON" button. Once this has been done, in the upper part of mig-t, you will find all the tabs of the sessions declared in the tests, you need to fill them with the corresponding session track.

If you declared more than one session in one test, you need to specify and start a different proxy for each session used. This is because there has to be a way to differentiate the traffic between the two sessions. To do that, go to "session config" tab in mig-t, (if you have already done the previous part you should see all the sessions you declared in your tests associated with a port) now, you need to change the port according to different proxies that you need to start from the Burp settings. Then press save.

Now go back to Input JSON, and press Execute Test Suite.

Once the tests have been executed, you will see the result in the "Test Suite Result" and by clicking on a result, you can see in details the matched messages in the tab "Test results".

If you want to see the entire history of the messages go to "proxy" tab in Burp, then "HTTP history"

</details><br>

## How to compile the plugin
The project is based on maven, you have two ways of compiling it

### With IntelliJ IDEA

<details>
  <summary>Details</summary>
The folder tool is an intelliJ project, if you open it with intelliJ IDEA it should be easier to compile: just go to `view > Tool Windows > Maven` and doubleclick on package under lifecycle.
</details><br>

### Without IntelliJ IDEA
<details>
  <summary>Details</summary>
You don't need to use IDEA to compile the project, you can install maven, go to the project direcotry `tool` mentioned before and type

```bash
mvn install
mvn package
```

If the project builds, the output jar should be located in the folder `tool/target/`

Two jar will be generated:

```
*-with-dependencies.jar
*.jar
```

You have to use the jar that has "-with-dependencies" in its name, the other will not work in burp.
</details><br>

## Documentation
You can find the documentation about the language used by the tool in the `doc/` folder. The documentation about the code is not yet finished, but all the functions are documented in the code.

## Known Bugs

-   Sometimes when re-executing a suite of active tests, the messages are not edited. Restart the plugin
-   On windows, the re-signing of the SAML messages sometimes will fail

# License
```
Copyright 2023, Fondazione Bruno Kessler

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

Developed within [Security & Trust](https://st.fbk.eu/) Research Unit at [Fondazione Bruno Kessler](https://www.fbk.eu/en/) (Italy)

## Other software licenses
### SAMLRaider License
Some parts of the tool that manages SAML certificates has been built by using portions of SAMLRaider code (https://github.com/CompassSecurity/SAMLRaider).

