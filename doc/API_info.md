# Info about the used Burp's APIs
The tools uses a series of Burp's APIs to interface with the Burp's proxy and interface. Burp's APIs are basically java classes that have methods to be implemented.

## Burp Java interface classes used
IBurpExtender
IBurpExtenderCallbacks
IExtensionHelpers
IHttpRequestResponse
IHttpRequestResponsePersisted
IInterceptedProxyMessage
IMessageEditor
IProxyListener
IRequestInfo
IResponseInfo
ITab
IBurpExtenderCallbacks
IExtensionHelpers
IHttpService
IMessageEditor
IMessageEditorController
IParameter

## Specific mappings between language and API "calls"

### Intercept messages
```json
{
    "action": "intercept",
    //...
}
```
It uses
```
IProxyListener.processProxyMessage()
```
that is a callback invoked when a new message is received.

### Filter messages by message type
```json
{
    "message type": "fb_login",

    //...
}
```
It uses
```java
IHttpRequestResponsePersisted.getRequest()
IHttpRequestResponsePersisted.getResponse()
IHttpRequestResponsePersisted.getHttpService()
IHttpService.getHost()
IHttpService.getPort()
IHttpService.getProtocol()
IExtensionHelpers.analyzeRequest()
IExtensionHelpers.analyzeResponse()
```
To check if the given message is the one specified in the corresponding msg_type.json file

### Replace request or response

```json
{
    "replace request": "request_name",
    //
}
```
It uses
```java
IHttpRequestResponse.setRequest()
IHttpRequestResponse.setResponse()
```

### Message check or manipulation
```java
IRequestInfo.getBodyOffset()
IResponseInfo.getBodyOffset()
```