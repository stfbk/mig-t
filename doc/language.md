# Language documentation

## Syntax

![image](https://lucid.app/publicSegments/view/351770fa-bf08-4d90-b8f0-6870783efd21/image.png)

## Test Suite

A test suite contains a list of tests, it is defined by:

- `name`
- `description`
- `tests` The list of all the tests
- `message filtering` (optional) default true, set it to false if you don't want the messages to be filtered while recording them for passive tests. The filter discards images, fonts, and other unwanted messages.

## Test

A test is defined by:

- `name`
- `description`
- `type` can be either `active` or `passive`
- `sessions` which is a list of session names. Both for active and passive tests is required to give at least one session as input
- `operations` contains a list of operations to be done on this test
- `result` only for active tests, it specify when a test should be considered successfully accomplished
- `references` used to specify infos about the reference of the specified test
- `violated_properties` used to specify infos about the violated properties of the test
- `mitigations` used to specify infos about the possible mitigations of the test

## Operation

An operation could be a message interception or a session operation, it could also be a validate operation (more info down here).
The most basic and useful type of operation is the one that makes you able to intercept message that you can then edit, just specify message type and the required tags and you are ready to go.
The use of the operation tag differ based on the type of test is defined into:

### Message type

With the tag `message type` it has to be specified to which message execute the given operation. Message types can be defined in the file _"msg_def.json"_ which will be created at the first execution of the plugin in the Burp folder. By default, some oauth message types are present, feel free to add or modify them.
The way a message type is defined is by the use of checks (like in passive tests), the checks are then evaluated over a message, and if the evaluation is successful, the message is then processed.

To define a message type you have to tell:

- The `name`
- `is request` if the message is a request or not (true, false)
- `response name` (optional) if you want to also associate a name to the response of that message (often useful when you know the request but not the response)
- `request name` (optional) if you need to intercept a message by its response, but you want do access the request, just put the name of the request to use it in the language. Note that if you intercept the response, you can not edit the request anymore, because it has already been sent.
- `checks` list (see check section for details)

### Operation in passive tests

When an operation in a passive test is defined with the `message type` tag, the other possible tags are (in an exclusive way):

- `checks`: which is a list of `check`

To consider a test successful all the checks has to be evaluated to true.
Note that where you are using a regex you have to backslash (\) all the regex operators such as (?{}.\*) if you need them to be searched instead of executed.

### Operation in active tests

An operation in an active test can be used with these tags:

- `message type` which specifies a message type
- `action` The action to be done on this operation, can be `intercept` or `clear cookies`
- `from session` specify which session has to be sniffed to search for the message, default is the standard session
- `then` the action to be done on the intercepted message after the execution of the operation, `forward` or `drop` (default forward)
- `save` saves the intercepted message to the given variable name

- `preconditions` dependig on their result the `Message operations` are executed or not. If a precondition fails, the entire test is considered not supported. The preconditions are defined as a list of `check` elements
- `message operations` List of `message operation` to do on the message. See the proper section for details
- `replace request` used with the name of a variable containing a message. It replaces the request of the intercepted message with a saved message.
- `replace response` used with the name of a variable containing a message. It replaces the response of the intercepted message with a saved message.

Note that in active tests the operations are evaluated sequencially, this means that until an operation has not been finished (i.e. the message is not arrived yet) the next operation will not be available. This eventually means that if you have more message filtering operations, only one at the time is executed.

### Operation and session in active tests

There is the possibility to handle different sessions in an active test, for example to replay messages.
A session has to be defined in the `sessions` tag in a `Test`, then it can be started with an operation with:

- tag `session` associated with the name of which session is reffering to,
- tag `action` the action to do on that session, like _start_, _stop_, _clear cookies_, _pause_, _resume_

#### Note with sessions in Burp

Burp has to be manually configured to open more proxy ports, based on the number of contemporary sessions to be executed. To do so, go to the proxy tab in burp, options, and then add enough port for your sessions.
You have also to link each of your sessions to a port, to do so, go to the plugin, after you read your JSON input test suite, in the session config tab write the ports you have previously defined. Note that the port has to be _different for each contemporary session_, otherwise the tests will not work.

## Message section

A message is divided in three parts

- `url` only for requests, is the message whithout head and without body
- `head` is the message without body and without url
- `body` is the message without head and without url

## Message Operations

The message operations are operations to be done on the intercepted message in an operation.
The syntax contains always the `from` tag, which specifies the message section where to search to do the given action (url, body, head). Then we have the possible actions:

- `remove match word` it removes the matched string, can be fed with a regex
- `remove parameter` with value the name of the parameter to be removed. A variant of the previous, it removes the parameter searched with its value
- `edit` edits the given parameter's value, the tag `in` specifies in what has to be edited
- `edit regex` edits the content matched by the passed regex with the content specified in `in` tag.
- `save` it saves the given parameter's value, in a variable with name taken from `as` tag.
- `save match` is saves the matched string in a variable with name taken from `as` tag
- `add` add a header with the name specified, and with value specified with `this`.

An example could be:

```json
"message operations": [
    {
        "from": "url",
        "edit": "state",
        "in": "newstatecode"
    }
]
```

or to save could be,

```json
"message operations": [
    {
        "from": "head",
        "save": "code",
        "as": "myVariable"
    }
]
```

### Note for body section

If you choose the body section, the meaning of the tags is different, infact:

- `remove match word` is equal to `remove parameter`, the value of these tags is treated as a regex which matches the entire body, all the matches are removed.
- `edit` is associated with a regex, substituting everything that matches that regex with the value of the `in` tag
- `save` is associated with a regex, it saves what is matched by that regex, saving it in a variable with name specified in `as` tag
- `add`is associated with an empty string, teh value will be appended to the body, the value do add is specified with the tag `this` (or `use` in case of a value from a variable)

Note that the content lenght of the body section is automatically updated or removed

## Decode operation

A list of decode operations can be added to each Operation (passive or active). These operations are used to decode encoded content taken from inside an intercepted message. A decode operation can have its own list of decode operations; these are called recursive decode ops. and they take as input the previously decoded content.

The HTTP parameter containing the content to be decoded has to be specified with the `decode param` If the section of the message is 'body,' the `decode param` takes a regex (for more information, see the section below).

Next, a list of encodings (or the `type`) has to be specified. You can specify an encodings list with the tag `encodings` the order of these encodings will be followed while decoding, and when the message is re-encoded, the order will be reversed. With the tag `type` the content is decoded following a fixed set of rules (e.g., jwts or XML). If you specify the `type` tag, the `encodings` tag will be ignored. If you use the `type` tag when using Edit Operations, you may be allowed to use more tags (e.g., with jwts or XML) to edit easily; otherwise, the decoded content will be used as plain text.

In decode operations is possible to use check operations to check the decoded content, depending on the specified type, the allowed check operations differ.

- JWT type -> See 'Checks on JSON content' section
- No type (encodings used) -> See check section

Needed tags:

- `type` and/or `encodings`
- `decode param`
- `from` select from where decode the content (HTTP message section or previous decode output)

optional tags:

- `decode operations`
- `checks`
- `edits`

#### Body section

An important note about the body (from) section is that the input of `decode param` has to be a regex, and whatever is matched with that regex is decoded.
An useful regex to match a parameter's value could be `(?<=SAMLResponse=)[^$\n& ]*` which searches the SAMLResponse= string in the body, and matches everything that is not $ or \n or & or whitespace

#### Decoding JWTs

When decoding a jwt (by using tag type=jwt) it is possible to check the signature of that jwt by providing a public key. To do this, use the `jwt check sig` tag with value the PEM-encoded public key to be used to check.

Note: The supported algorithms for signing are:

- RS256
- RS512

#### Decoding JWE

Note that when decrypting a JWE, a JWS is expected in the payload. Other payloads are not supproted.

To decrypt a JWE to access the JWT in its payload use these tags

- `jwe decrypt` with the private key in PEM string format
- `jwe encrypt` with the public key in PEM string format

Note: You can decrypt without specifying encrypt, this will prevent the JWE from being edited (as no encryption key is passed)
Note: You can't encrypt, without decrypt

Note: Supported algorithms are:

- RSA_OAEP
- RSA_OAEP_256
- ECDH_ES_A128KW
- ECDH_ES_A256KW

## Tag table

In this table you can find a description of all the tags available for this Operation based on the input Module.

| input module (container)    | Available tags    | Required | value type             | allowed values                         |
| --------------------------- | ----------------- | -------- | ---------------------- | -------------------------------------- |
| standard Operation          | from              | yes      | str                    | head, body, url                        |
|                             | decode param      | yes      | str                    | \*                                     |
| decode Operation (type=jwt) | from              | yes      | str                    | jwt header, jwt payload, jwt signature |
|                             | decode param      | yes      | str(JSON path)         | \*                                     |
| \*                          | type              |          | str                    | xml, jwt                               |
|                             | encodings         |          | list[str]              | base64, url, ..                        |
|                             | decode operations |          | list[decode Operation] | \*                                     |
|                             | checks            |          | list[check Operation]  | \*                                     |
|                             | edits             |          | list[edit Operation]   | \*                                     |
|                             | jwt check sig     |          | str(PEM)               | PEM-encoded public key                 |
|                             | jwe decrypt       |          | str(PEM)               | PEM-encoded private key                |
|                             | jwe encrypt       |          | str(PEM)               | PEM-encoded public key                 |

### Recursive Decode operations

When using the `from` tag in a recursive decode (one that is inside another), you can use - depending on the previous decode type - other sections, such as "jwt header" "jwt payload" ..

Source: standard Operation (HTTP intercepted message)

- `from`: (url, head, body)

Source: decode Operation JWT

- `from`: (jwt header, jwt payload, jwt signature)

in recurdsive decode ops, the decode param accepts different inputs, e.g. if previous decoded content is a jwt, decoded content will accept a JSON path

Syntax example of a recursive decode operation:

```json
"decode operations": [
  {
    ...,
    "decode operations": [
      {
        "from": "somwhere in the previous decode",
        "encodings": "asdasd",
      }
    ]
  }
]
```

Example of decoding a jwt from the url of a message in the asd parameter, and then decode the jwt found inside of the jwt.

```json
"decode operations": [
  {
    "from": "url",
    "type": "jwt",
    "decode param": "asd",
    "decode operations": [
      {
        "from": "jwt header",
        "type": "jwt",
        "decode param": "$.something"
      }
    ]
  }
]
```

### Using Edit Operation in Decode Operations

It is possible to edit the decoded content of decode Ops by using edit Operations. A list of edit Operations has to be specified. When using Edit Op. inside Decode Operations, depending on the `type` specified in Decode Operations, you can use different keys.

- `type`: JWT
  - `jwt from` specifies the section of the jwt to edit (header, payload, signature)
  - `jwt edit` JSON path of the key to edit
  - `jwt remove` JSON path of the key to remove
  - `jwt add` JSON path to the key to add + `value` with name
  - `jwt save` JSON path to the key to save
  - `value` used with edit or add, to specify the value of the key
- `type`: XML
  - see next XML section
- no `type` specified, (treated as plain text):
  - Using `txt remove` the matched text will be removed from the text
  - Using `txt edit` the matched text will be edited with the text specified in `value` tag
  - Using `txt add` the text specified in `value` will be inserted at the end of the matched text
  - Using `txt save` the matched text will be saved in a variable having the name specified in tag `as`

#### JWT type

This type is used to edit decoded JWT tokens. This way is possible to edit, add, save or resign them. The possible actions are:

- `jwt from` Used to specify the section of the token to execute the given action, choose btween:
  - `header`
  - `payload`
  - `signature`
- `jwt remove` If used on signature removes the entire signature
- `jwt edit` `value` If used on signature edits the entire signature.
- `jwt add` `value`
- `jwt save` `as` if used on sinature saves the entire signature
- `jwt sign` Specifying a PEM-encoded private key that will be used to sign the jwt

##### Note on signing

When signing a jwt, the supported algorithms are:

- RS256
- RS512

##### Example

Edit the scope claim inside an OAuth request jwt

```json
"decode operations": [
  {
    "from": "url",
    "type": "jwt",
    "encodings": [],
    "decode param": "(?<=authz_request_object=)[^$\n& ]*",
    "edits": [
      {
        "jwt from": "payload",
        "jwt edit": "$.scope",
        "value": "wrong_scope"
      }
    ]
  }
]
```

Check the scope claim inside an OAuth request jwt

```json
"decode operations": [
  {
    "from": "body",
    "decode param": "(?<=authz_request_object=)[^$\n& ]*",
    "encodings": [],
    "type": "jwt",
    "checks": [
      {
        "in": "payload",
        "check": "$.scope",
        "is": "openid"
      }
    ]
  }
]
```

#### XML type

The available XML actions are:

- Remove tag
  - use `remove tag` with the tag name
- Remove tag's attribute,
  - use `remove attribute` with the attribute name
  - the name of the tag which contains the attribute has also to be specified using `xml tag`
- Edit tag value
  - use `edit tag` with the tag name
  - use `value` to specify the new value
- Edit attribute value
  - use `edit attribute` with the attriute name
  - the name of the tag containing the attribute has also to be specified using `xml tag`
- Add tag
  - use `add tag` with the name of the tag to add
  - use `value` with the value of the tag to add
  - the name of the parent xml node to add the new node has to be specified with `xml tag`
- Add attribute
  - use `add attribute` with the attribute name
  - use `value` with the attribute value
  - the name of the tag to insert the new attribute into has to be specified with `xml tag`
- Save tag value
  - use `save tag` with the tag name
- Save attribute value
  - use `save attribute` with the attribute name
  - the name of the tag containing the attribute has also to be specified with `xml tag`

Note on the occurencies: If there are more elements that has the same tag name, you can use the tag `occurrency` specifying the index of the occurrency you want to edit, for example, if you have three tags named "person", but you want just to edit the third occurrency of that "person" tag, then you need to put three

An example:

```json
"message operations": [
  {
    "from": "url",
    "decode param": "SAMLRequest",
    "encoding": [
        "url",
        "base64",
        "deflate"
    ],
    "type": "xml",
    "edits": [
      {
        "edit tag": "samlp:AuthnRequest",
        "value": "new tag value"
      }
    ]
  }
]
```

Note on the namespace: the tag name comprehend the namespace i.e. if the tag you want to select is this:

```xml
<Something:apple></Something:apple>
```

in the tag name you have to specify "Something:apple"

#### TXT type

It is a type used to edit, remove, add, or save pieces of a decoded param that is treated as a text.
You have to specify a regex using the parameter "txt ..." with the associated action, the possible usages are:

- Using `txt remove` the matched text will be removed from the text
- Using `txt edit` the matched text will be edited with the text specified in `value` tag
- Using `txt add` the text specified in `value` will be inserted at the end of the matched text
- Using `txt save` the matched text will be saved in a variable having the name specified in tag `as`

#### Note for using saved variables

It is possible to use the tag `use` instead of the tag `value` to use the text saved in the variable specified using the `use` tag.

#### SAML signature

There's the possibility of remove the signature from a saml request or response and resign it with a test private key, just specify `self-sign`: true in the message operation.
Another possibility is just to remove the signature, using `remove signature` set to true in the message operation.
Note that this keys are avaiable and applied only on decoded parameters, also if `decode param` is defined.

## Session Operation

Session operations are used to edit the session tracks given the actual test progress.
Each session operation is composed by:

- `session` specifies wich session to do changes
- `save`, associated with tag `as` to specify the name of the variable. Available actions to be saved are:
  - `last_action`
  - `last_open`
  - `last_url`
  - `last_click`
  - `track` used to specify actions in the track to be saved as variable to be then used in an insert. Associated with tag `range` containing the from an to markers to specify the actions to be saved. For example "range: "[M0,ML]" or "(MO,ML]"
- `insert`it is possible to build a string composed by the variables previously saved like this: "sometext that is appended in the track with $variable_to_add$", it has to be specified also the tag `at` with a marker, to say where to put the inserted action. Default markers are M0 (start of the track), ML (end of the track).
- `remove` removes an action at the specified marker

Note that in `save` each element can be accessed trough `.elem`, otherwise the entire session action is considered. There is also the possibility of adding `.parent` to get the parent div element.

Note that during insertion, the element inserted is always positioned after the given marker.

### Examples

```json
{
  "session": "s2",
  "action": "start",
  "session operation": [
    {
      "session": "s2",
      "insert top": "cosescritte e $variabile$"
    }
  ]
}
```

Not sure about this ^^^ , not yet implemented ^^^^

```json
"session operation": [
    {
        "session": "s1",
        "save" : "last_action.elem",
        "as" : "elem"
    },
    {
        "session": "s1",
        "save" : "last_url",
        "as" : "url"
    },
    {
        "session" : "s1",
        "insert" : "open | $url$",
        "at" : "ML" // marker last
    },
    {
        "session" : "s1",
        "insert" : "snapshot | $elem$",
        "at" : "ML" // marker last
    },
    {
        "session" : "s1",
        "mark" : "last_click",
        "name" : "M1"
    },
    {
        "session": "s1",
        "save" : "",
        "from" : "M0", // marker zero, first action in track
        "to"    : "M1",
        "as"    : "qualcosa"
    }
]
```

## Checks and Check

The Checks tag is a list of Check elements, which can be defined with:

- `in` says were to check the given parameter, can be _head_, _body_, _url_
- `check` checks if the given string is present in the specified message section.
- `check param` specifies the name of the parameter to be checked, depending on the section choosed, the tool will search for the parameter using a pattern. (for the url, it will search for a query parameter, for the head, it will search for a head parameter)
- `check regex` specify a regex that checks the selected content by matching it.
  . `use variable` (true or false) set to true if you want to specify a variable name on the following tags, to check wrt to that variable value.
- The actual check on the value, which are self explanatory. (if none of these are specified, the check will only check if the given parameter is present)
  - `is`
  - `not is`
  - `contains`
  - `not contains`
  - `is present` specifying true or false, to check whether is present or not
  - `is in` the value is between a list of values
  - `is not in` the value is not between a list of values
  - `is subset of` used to check that a matched JSON array is a subset of the given array

Note that you can use `check regex` OR `check` OR `check param`.

Note that `check` accepts only the `is present` tag.

In passive tests the checks's result are intended as the entire test result, so all the checks has to pass to have a successfull test.

### Checks on JSON content

In case a check operation is executed inside an operation that gives a JSON as an output (e.g. decode operations with type=jwt), the check operation is enabled to use JSON paths to identify keys and values specified with `check` tag. The `in` tag specifies the section of the JWT (header, payload, signature). Note that signature is treated as plain text.

Note: when using `check regex` with json content, the specified content will be treated as plain text. e.g the header of a jwt will be treated as plain text, and the regex will be executed over the entire header.

Note: matched array contents will always be converted to string for simplicity. This means that if you want to check an integer or float, you should write it as a string (e.g. 12.3 -> "12.3")

```json
"decode operations": [
  {
    "tagsofadecode": "decodejwt",
    "checks": [
      {
        "in": "header",
        "check": "jsonpath",
        "is": "something"
      }
    ]
  }
]
```

### Note for the active tests

If you need to do a check on an active test, you have to do a `validate` operation, which is basically an operation where you can do checks

### Examples

Check using a variable value: check that the value of the header "Host" is equal to the value of the variable "var1"

```json
"checks" : [
  {
    "in": "head",
    "check param": "Host",
    "use variable": true,
    "is": "var1"
  }
]
```

## Preconditions

Preconditions are used in an operation of an active test to check something in the intercepted message before the execution of the message operations. If the checks in the preconditions are evaluated to false, the test is considered unsupported, not failed. Basically preconditions are a list of checks.
To use a precondition just write

```json
"preconditions" : []
```

filling the list wit the checks or regex you need.
Over the list of check or regex a AND operation is made, so all of the checks (or regex) in the list has to be successful to continue the test.

## Save

A message or a string can be saved with this tag. It can be used both in an operation, to save a message, and in a _Message Operation_ to save the value of a found parameter.

- `Save` associated with the name of the variable

There are two ways of using the value of a variable, depending of its type:

- Using a message-type variable: it can be used in an operation with the tag `action` set to intercept there is the possibility of use `replace request` (or `replace response`) with the name of the variable. This way the intercepted message's request (or response) is replaced with the specified variable value. Note that when a message is replaced, all the message operations in that operation will be ignored.
- Using a string-type variable: can be used in Message Operations, where you have to add or edit a parameter's value, writing `use` and the name of the variable
  <br>When saving and using variables, take care to assign a variable before its use

Note that when saving a variable, if the value is empty (no match or no parameter found), the MessageOperation (edit, add, ..) where the variable is used will not be executed, the execution will continue without errors.

## Result and oracle

The result tag is used in active tests to specify the oracle to be used, which are the criterias to which the test is evaluated.

it can be set to:

- `correct flow \[sessionname\]` the test succedes only if all the user actions specified in a session's track are executed without errors
- `incorrect flow \[sessionname\]` opposite of `correct flow`, the test succedes only if there is an error
- `assert_only` the test result ignores the validation of the session flow but gives a result depending on the assertions defined in the track. This means, that if the execution of the session fails, the result will not take it into account.

The result can be combined with the result of the checks in an operation.
The succes is evaluated with the Boolean operator AND between the result and all the results of the operations

Note that if correct (or incorrect) flow is used without specifying a session name, all the sessions are checked.

Note for the definition of the track: to have a successfull oracle we suggest to define a track that not only does the login of the user, but also performs some actions on the final page, this way the result of the track is more complete. (i.e. if we just tell to login, the track will not try to act on the logged page, this way the plugin has no clue on if the final page contains an error or not)

## Note on regex

Note that if you are filling a field where a regex is expected, you have to backslash (\) all the regex operators such as (?{}.\*) if you need them to be searched instead of executed.

## Test examples

### Example of with active tests

```json
{
  "test suite": {
    "name": "Test Suite 1 ",
    "description": "Description of the Test Suite"
  },
  "tests": [
    {
      // PKCE plain method
      "test": {
        "name": "PKCE plain method",
        "description": "Finds an authRequest and remove the parameter code_challenge_method",
        "type": "active", // active test type
        "sessions": ["main"],
        "operations": [
          // List of operations to do
          {
            "action": "intercept", // action to do
            "then": "forward",
            "message type": "authorization request", // intercept messages of type authorization request
            "preconditions": [
              {
                "check param": "state",
                "is present": true
              }
            ],
            "message operations": [
              // list of operations to do on message
              {
                "from": "url",
                "remove parameter": "code_challenge_method"
              }
            ]
          }
        ],
        "result": "correct flow" // it has to be a correct flow for a successful attack
      },
      "test": {
        "name": "PKCE plain method",
        "description": "Finds an authRequest and remove the parameter code_challenge_method",
        "type": "active",
        "sessions": ["s1", "s2"],
        "operations": [
          {
            "session": "s1",
            "action": "start"
          },
          {
            "action": "intercept",
            "from session": "s1",
            "then": "forward",
            "message type": "authorization request",
            "preconditions": [
              {
                "in": "url",
                "check param": "state",
                "is not": ""
              }
            ],
            "message operations": [
              {
                "from": "url",
                "save": "state",
                "as": "var_state"
              }
            ]
          },
          {
            "session": "s1",
            "action": "stop"
          },
          {
            "session": "s2",
            "action": "start"
          },
          {
            "action": "intercept",
            "from session": "s2",
            "then": "forward",
            "message type": "authorization request",
            "preconditions": [
              {
                "in": "url",
                "check param": "state",
                "is not": ""
              }
            ],
            "message operations": [
              {
                "from": "url",
                "edit": "state",
                "use": "var_state"
              }
            ]
          }
        ],
        "result": "incorrect flow s2"
      }
    }
  ]
}
```

### Example of with passive tests

#### Example 1: PKCE is used (TO BE CHANGED TO NEW LANGUAGE)

This passive test checks whether PKCE is used in an OAuth flow, checking if the authorization grant message contains the parameters "code_challenge" or "code_challenge_method", which are necessary to use PKCE. More precisely, the test:

1. The test is defined, specifying its Name, Description, and Type
1. The operation is defined
   1. Search for a message of type _"authorization request"_
   1. Apply the regex _"code_challenge|code_challenge_method"_ to the found message, in the section specified in body
   1. Check for the regex result, if one or more occurences are found, then the test is passed, otherwise the test is not passed.

```json
{
  "test suite": {
    "name": "Test Suite 01",
    "description": "Only Passive Test"
  },
  "tests": [
    {
      "test": {
        "name": "PKCE is used",
        "description": "test 2",
        "type": "passive",
        "sessions": ["main"],

        "operations": [
          {
            "message type": "Authorization request",
            "regex": "code_challenge|code_challenge_method",
            "message section": "body"
          }
        ]
      }
    }
  ]
}
```

#### Other passive tests (TO BE CHANGED TO NEW LANGUAGE)

```json
{
  "test suite": {
    "name": "Test Suite 01",
    "description": "Only Passive Test"
  },
  "tests": [
    {
      "test": {
        "name": "Compliance to Standard",
        "description": "test 1",
        "type": "passive",
        "sessions": ["main"],
        "operations": [
          {
            "message type": "authorization request",
            "checks": [
              {
                "in": "head",
                "check": "response_type",
                "is": "code"
              },
              {
                "in": "head",
                "check": "client_id"
              }
            ]
          }
        ]
      }
    },
    {
      "test": {
        "name": "PKCE is implemented",
        "description": "check for common params presence",
        "type": "passive",
        "sessions": ["main"],
        "operations": [
          {
            "regex": "code_challenge|code_challenge_method",
            "message type": "authorization response",
            "message section": "body"
          }
        ]
      }
    },
    {
      "test": {
        "name": "Using HTTPS",
        "description": "https is used for all messages",
        "type": "passive",
        "sessions": ["main"],
        "operations": [
          {
            "regex": "^https",
            "message type": "oauth request",
            "message section": "url"
          },
          {
            "regex": "^https",
            "message type": "oauth response",
            "message section": "url"
          }
        ]
      }
    }
  ]
}
```

# Session Track (User actions)

The session track is a list of user actions, it tells the browser what actions to do. The session track is defined in a custom language that extends the one defined by [Katalon-Recorder sample plugin](https://github.com/katalon-studio/katalon-recorder-sample-plugin) they call it "sample for new formatters".

Basically, each User Action is an action to be done on the browser that simulates an user. The standard possible actions are:

- `open` Opens the given url
- `click` Clicks on the specified HTML element
- `type` Type on the specified HTML element the specified text

The syntax is as follows <br>
`<action> | <elem> | <content>` <br>
Note that the `< >` should not be included

### Example

```
open | https://webpage.it/ |
click | link=login |
type | id=username | mail@gmail.com
type | id=password | mail_password
click | link=login |
click | xpath=/html/body/div/button/ |
```

## Other special actions

### Wait action

`wait` command, that is used to tell the browser to wait n millisecond before executing the next action. usage: `wait | 3000 "

### Clear cookies action

`clear cookies` command, which will clear all the cookies in the current session, usage: "clear cookies |"

### Asserts on session

The session can include the asserts, the asserts are a way to validate that the session flow is going how it is supposed to.
The possible asserts to be used are:

- `assert clickable` Make sure that an html object is clickable
- `assert not clickable` Make sure that an html object is not clickable
- `assert visible` Make sure that an html object is visible
- `assert not visible` Make sure that an html object is not visible
- `assert element content is` Make sure that the content of the specified element is as specified in `<content>`
- `assert element content has` Make sure that the element content of the specified element contains the string specified in `<content>`
- `assert element class is` Make sure the class of the element is as specified in the `<content>`
- `assert element class has` Make sure one of the classes of the html element contains the string specified in the `<content>`
- `assert element has attribute` Make sure one of the attributes of the element is as specified in `<content>`
- `assert element not has attribute` Make sure the element doesn't have the attribute specified in `<content>`

Syntax is as follows: <br>
`<assert> | <elem> | <content>` <br>

Examples: <br>
`assert clickable | xpath=/body/.. |`<br>
`assert not visible | id="elem" |`<br>
`assert element content is | xpath=/body/div/label | text to match`<br>
`assert element class has | xpath=/body/... | class_to_match`<br>

# Changelog

## v1.4.0

- Added decode operations
- Removed "decode parameter" from Message Operation
- Added checks in decode operations
- Added support for Checks to work with JSON content
- Changed tag `encoding` in `encodings`
- Added edit Operation
- Moved tags used to modify decoded content in Message Operations to Edit Operation inside Decode Operation
- Removed `raw header` `raw payload` `raw signature` from `jwt from` tag in Decode Operation
- Added supprot of regex in checks (in future they will substitute existing regex)
- Remove support for hardcoded standard message types such as oauth request and oauth response
- Removed support for hardcoded identification of OAuth flow
- removed `request`, `response`, `oauth request` `oauth response` from Message type
- removed `regex` and `message section` tag from Message Type, now only checks are available (that contains also regex)
- removed `regex` from Operation in passive tests
- Removed validate Operation, now just use checks inside an intercept Operation
- Removed OAuth metadata tag in test
- Added signing of decoded jwt with private key inside Edit Operation
- Added check of signature of jwt inside the decode operation
