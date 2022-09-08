
# ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/core/images/project_color_16x16.png?raw=true "Project") lib_OAuth

OAuth/OpenID library to perform authentication.
This library work in Conjunction with the Ngx Client Action [OAuth/OpenID](https://doc.convertigo.com/documentation/latest/reference-manual/convertigo-objects/mobile-application/components/action-components/oauth-openid)

## Symbols
OAuth work in conjunction with applications declared in the providers API portals. Please refer to the documentation fo each provider for details. When you declare an application, the portal will provide you with various IDs you will be able to configure in the following symbols.

|----------|-------------------|
|Symbol    | Comment           |
|----------|-------------------|
|lib_oauth.google.clientid    | The Google client id of your registered app on Google API portal           |
|lib_oauth.google.keysecret.secret    | The Google secret key of your registered app           |
|lib_oauth.azuread.clientid    | The Azure client id of your registered app on Microsoft Application Registration Portal (https://apps.dev.microsoft.com)    |
|lib_oauth.azuread.tenantid    | The optional Azure tenant id you will find in the same portal           |
|lib_oauth.linkedin.clientid    | The linkedIn client id you will find the LinkedIn API portal (https://www.linkedin.com/secure/developer?newapp           |
|lib_oauth.linkedin.keysecret.secret    | The linkedIn secret key you will find in the same portal           |


<details><summary><span style="color:DarkGoldenRod"><i>Connectors</i></span></summary><blockquote><p>


<details><summary><b>GoogleOAuth</b></summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/connectors/images/httpconnector_color_16x16.png?raw=true "HttpConnector") GoogleOAuth



<details><summary><span style="color:DarkGoldenRod"><i>Transactions</i></span></summary><blockquote><p>


<details><summary><b>Default_transaction</b></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/httptransaction_color_16x16.png?raw=true "HttpTransaction") Default_transaction


</p></blockquote></details>

<details><summary><b>DiscoveryDocument</b></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/jsonhttptransaction_color_16x16.png?raw=true "JsonHttpTransaction") DiscoveryDocument


</p></blockquote></details>

<details><summary><b>GetToken</b></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/jsonhttptransaction_color_16x16.png?raw=true "JsonHttpTransaction") GetToken



<span style="color:DarkGoldenRod">Variables</span>

<table>
<tr>
<th>
name
</th>
<th>
comment
</th>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;client_id
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;client_secret
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;code
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;grant_type
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;redirect_uri
</td>
<td>

</td>
</tr>
</table>

</p></blockquote></details>
</p></blockquote></details>
</p></blockquote></details>

<details><summary><b>LinkedInApi</b></summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/connectors/images/httpconnector_color_16x16.png?raw=true "HttpConnector") LinkedInApi



<details><summary><span style="color:DarkGoldenRod"><i>Transactions</i></span></summary><blockquote><p>


<details><summary><b>getEmail</b></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/jsonhttptransaction_color_16x16.png?raw=true "JsonHttpTransaction") getEmail


</p></blockquote></details>

<details><summary><b>Me</b></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/jsonhttptransaction_color_16x16.png?raw=true "JsonHttpTransaction") Me


</p></blockquote></details>
</p></blockquote></details>
</p></blockquote></details>

<details><summary><b>LinkedInOAuth</b></summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/connectors/images/httpconnector_color_16x16.png?raw=true "HttpConnector") LinkedInOAuth



<details><summary><span style="color:DarkGoldenRod"><i>Transactions</i></span></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/jsonhttptransaction_color_16x16.png?raw=true "JsonHttpTransaction") Authorize



<span style="color:DarkGoldenRod">Variables</span>

<table>
<tr>
<th>
name
</th>
<th>
comment
</th>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;client_id
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;client_secret
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;code
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;grant_type
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableHttpVariable" >&nbsp;redirect_uri
</td>
<td>

</td>
</tr>
</table>

</p></blockquote></details>
</p></blockquote></details>

<details><summary><b>MicrosoftGraphApi</b></summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/connectors/images/httpconnector_color_16x16.png?raw=true "HttpConnector") MicrosoftGraphApi



<details><summary><span style="color:DarkGoldenRod"><i>Transactions</i></span></summary><blockquote><p>


<details><summary><b>default</b></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/httptransaction_color_16x16.png?raw=true "HttpTransaction") default


</p></blockquote></details>

<details><summary><b>Me</b></summary><blockquote><p>


### ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/transactions/images/jsonhttptransaction_color_16x16.png?raw=true "JsonHttpTransaction") Me


</p></blockquote></details>
</p></blockquote></details>
</p></blockquote></details>
</p></blockquote></details>

<details><summary><span style="color:DarkGoldenRod"><i>Sequences</i></span></summary><blockquote><p>


<details><summary><b>checkAccessOpenID</b> : Checks is a valid access token is held by the current users' session for AzureAD</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") checkAccessOpenID

Checks is a valid access token is held by the current users' session for AzureAD

This has to be called by client apps to decide whenever or not they have to display an OAuth login screen


</p></blockquote></details>

<details><summary><b>checkAccessToken</b> : Checks is a valid access token is held by the current users' session for AzureAD</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") checkAccessToken

Checks is a valid access token is held by the current users' session for AzureAD

This has to be called by client apps to decide whenever or not they have to display an OAuth login screen


</p></blockquote></details>

<details><summary><b>checkAccessTokenGoogle</b> : Checks is a valid access token is held by the current users' session for Google</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") checkAccessTokenGoogle

Checks is a valid access token is held by the current users' session for Google

This has to be called by client apps to decide whenever or not they have to display an OAuth login screen


</p></blockquote></details>

<details><summary><b>checkAccessTokenLinkedIn</b> : Checks is a valid access token is held by the current users' session for LinkedIn</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") checkAccessTokenLinkedIn

Checks is a valid access token is held by the current users' session for LinkedIn

This as to be called by client apps to decide whenever or not they have to display an OAuth login screen


</p></blockquote></details>

<details><summary><b>GetOAuthCredentials</b> : Returns to the client the public OAuth credentials</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") GetOAuthCredentials

Returns to the client the public OAuth credentials
</p></blockquote></details>

<details><summary><b>loginAzureAdWithAccessToken</b> : Perform the Backend OAuth flow for AzureAD</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") loginAzureAdWithAccessToken

Perform the Backend OAuth flow for AzureAD

If the token is valid, it will be stored in the user's session to be used when calling Microsoft APIs. Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


<span style="color:DarkGoldenRod">Variables</span>

<table>
<tr>
<th>
name
</th>
<th>
comment
</th>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;access_token
</td>
<td>
The Access Token
</td>
</tr>
</table>

</p></blockquote></details>

<details><summary><b>loginGoogleWithCode</b> : Perform the Backnd OAuth flow for Google</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") loginGoogleWithCode

Perform the Backnd OAuth flow for Google

If the token is valid, it will be stored in the user's session to be used when calling Google APIs. Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


<span style="color:DarkGoldenRod">Variables</span>

<table>
<tr>
<th>
name
</th>
<th>
comment
</th>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;client_id
</td>
<td>
The Client ID provided by a symbol. (This is never provided by the client)
</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;code
</td>
<td>
The OAuth CODE provided by the client
</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;keySecret
</td>
<td>
The OAuth secret key provided by a Symbol (This is never provided by the client)
</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;redirect_uri
</td>
<td>
The Google OAuth redirect as configured in the Google Application registration
</td>
</tr>
</table>

</p></blockquote></details>

<details><summary><b>loginLinkedInWithCode</b> : Perform the OAuth flow for LinkedIn</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") loginLinkedInWithCode

Perform the OAuth flow for LinkedIn

If the token is valid, it will be stored in the user's session to be used when calling LinkedIn APIs. Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


<span style="color:DarkGoldenRod">Variables</span>

<table>
<tr>
<th>
name
</th>
<th>
comment
</th>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;client_id
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;code
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;keySecret
</td>
<td>

</td>
</tr>
<tr>
<td>
<img src="https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/variables/images/variable_color_16x16.png?raw=true "  alt="RequestableVariable" >&nbsp;redirect_uri
</td>
<td>

</td>
</tr>
</table>

</p></blockquote></details>

<details><summary><b>SignOut</b> : Sign out from App</summary><blockquote><p>


## ![](https://github.com/convertigo/convertigo/blob/develop/engine/src/com/twinsoft/convertigo/beans/sequences/images/genericsequence_color_16x16.png?raw=true "GenericSequence") SignOut

Sign out from App.. Warning must be called with disableAutologin to true !
</p></blockquote></details>
</p></blockquote></details>
