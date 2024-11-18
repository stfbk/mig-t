# MIG-T Pentesting Tool

MIG-T Pentesting Tool is a plugin for BurpSuite that helps security testers automate their testing activities. It allows the tester to define automations to edit or check correctnees of HTTP messages. It integrates an automated browser used to simulate user actions on a webpage, to trigger specific messages. It uses a machine-readable JSON language to define tests that will be executed by MIG-T<br>

## Quickstart

<details>
  <summary>Details</summary>
We suggest you to download the lastest release of the tool from the release page, otherwise you can compile the last version from the source code by following the steps described in the "[how to compile the plugin](#how-to-compile-the-plugin)" section.

## Download & start the tool

1. download from the release page the last version of the tool, select the jar which ends with `with-dependencies`, or compile the source code.
2. Download the last version of [Burp Suite Community Edition](https://portswigger.net/burp/releases/community/latest)
3. Start Burp and go in the _Exstensions_ tab
4. Press _Add_ button
5. In the _Extension file (.jar)_ select the tool jar you downloaded before
6. Now the plugin should be loaded, go to the "MIG-T" tab, and you can start using it. For more info on how to start testing, check out the [wiki](https://github.com/stfbk/mig-t/wiki)

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
You don't have to use IDEA to compile the project, you can install maven, go to the project direcotry `tool` mentioned before and type

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

Documentation about MIG-T and the language can be found in this repo's [wiki](https://github.com/stfbk/mig-t/wiki)

# MIG-T API Documentation

Explore the API endpoints and documentation here: <https://app.swaggerhub.com/apis-docs/PGSENO02/MIG-TAPIs/1.0.0#/>

### API Endpoints

MIG-T supports both GUI and API interaction. Two endpoints are available for API interaction:

<details>
  <summary>Details</summary>

#### /execute [POST]

Check the validity of the test and run the test. 

Input: 
```json
{
  "test": "test content",
  "sessions": {
    "session_name_1": "session content",
    "session_name_2": "session content"
  }
}
```

Output:
- HTTP status code 200 (ok)

#### /result [GET]

Checks whether the test is finished and returns the result.

Output:
- If the test is not finished:
```json
{
  "finished": false
}
```
- If the test is finished:
```json
{
  "finished": true,
  "tests": [
    {
      "references": "",
      "test name": "",
      "description": "",
      "type": "",
      "mitigations": "",
      "result": ""
    }
  ]
}
```
A verbose parameter is available (`/result?verbose=true`) to retrieve data from requests. For example:
```json
{
  "finished": true,
  "tests": [
    {
      "references": "",
      "test name": "Does the OP release Access Tokens with the use of refresh tokens",
      "description": "In this test the offline access flow is accomplished and a refresh token is obtained. After this, a new token request is done with \"grant_type\u003drefresh_token\" and the refresh token inserted in the \"refresh_token\" parameter. The response must include the Access Token",
      "type": "active",
      "mitigations": "",
      "result": "success",
      "details": [
        {
          "message type": "Authentication request",
          "request": "base64_of_the_request"
        }
      ]
    }
  ]
}
```
</details><br>

# Contributors

The following is a list of FBK employees and collaborators who have contributed to the development of the tool:

- [Andrea Bisegna](https://st.fbk.eu/people/andrea-bisegna)
- [Matteo Bitussi](https://st.fbk.eu/people/matteo-bitussi)
- [Simone Brunello](https://st.fbk.eu/people/simone-brunello)
- [Roberto Carbone](https://st.fbk.eu/people/roberto-carbone)
- [Laura Cristiano](https://cs.fbk.eu/people/laura-cristiano)
- [Pietro De Matteis](https://rising.fbk.eu/people/pietro-de-matteis) (FBK & DedaGroup)
- [Eleonora Marchesini](https://st.fbk.eu/people/eleonora-marchesini)
- [Silvio Ranise](https://cs.fbk.eu/people/silvio-ranise)


Following is the list of students that contributed to the evolution of the tool, and their corresponding thesis.

- Pier Guido Seno (Bachelor's Thesis, University of Trento, 2024) From Local to Remote: Enhancing MIG-T Pentesting Tool with SaaS for Securing Digital Identity
- Matteo Bitussi (Bachelor's Thesis, University of Trento, 2022) Declarative Specification of Pentesting Strategies for Browser-based Security Protocols: the Case Studies of SAML and OAuth/OIDC
- Wendy Barreto (Bachelor's Thesis, University of Trento, 2021) Design and implementation of an attack pattern language for the automated pentesting of OAuth/OIDC deployments
- Stefano Facchini (Bachelor's Thesis, University of Trento, 2020) Design and implementation of an automated tool for checking SAML SSO vulnerabilities and SPID compliance
- Claudio Grisenti (Bachelor's Thesis, University of Trento, 2020) A pentesting tool for OAuth and OIDC deployments
- Ivan Martini (Bachelor's Thesis, University of Trento, 2018) An automated security testing framework for SAML SSO deployments
- Valentina Odorizzi (Bachelor's Thesis, University of Trento, 2018) Progettazione e sviluppo di uno strumento per l'analisi automatica di vulnerabilità "Missing XML Validation" in SAML SSO
- Giulio Pellizzari (Bachelor's Thesis, University of Trento, 2018) Design and implementation of a tool to detect Login Cross-Site Request Forgery in SAML SSO: G Suite case study

# License

```
Copyright 2024, Fondazione Bruno Kessler

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

Developed within [Security & Trust](https://st.fbk.eu/) Research Unit at [Fondazione Bruno Kessler](https://www.fbk.eu/en/) (Italy) in collaboration with [Istituto Poligrafico e Zecca dello Stato](https://www.ipzs.it/) (Italy) and Futuro & Conoscenza.

## Other software

### SAMLRaider

Some parts of the tool that manages SAML certificates has been built by using portions of SAMLRaider code (<https://github.com/CompassSecurity/SAMLRaider>).

### nimbus-jose-jwt

Parts of the tool that manage JWTs has been built using nimbus-jose-jwt
<https://connect2id.com/products/nimbus-jose-jwt>
