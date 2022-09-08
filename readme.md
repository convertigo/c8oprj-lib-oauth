


# lib_OAuth

OAuth/OpenID library to perform authentication.
This library work in Conjunction with the Ngx Client Action [OAuth/OpenID](https://doc.convertigo.com/documentation/latest/reference-manual/convertigo-objects/mobile-application/components/action-components/oauth-openid)

## Symbols


 


For more technical informations : [documentation](./project.md)

- [Installation](#installation)
- [Sequences](#sequences)
    - [checkAccessOpenID](#checkaccessopenid)
    - [checkAccessToken](#checkaccesstoken)
    - [checkAccessTokenGoogle](#checkaccesstokengoogle)
    - [checkAccessTokenLinkedIn](#checkaccesstokenlinkedin)
    - [GetOAuthCredentials](#getoauthcredentials)
    - [loginAzureAdWithAccessToken](#loginazureadwithaccesstoken)
    - [loginGoogleWithCode](#logingooglewithcode)
    - [loginLinkedInWithCode](#loginlinkedinwithcode)
    - [SignOut](#signout)


## Installation

1. In your Convertigo Studio use `File->Import->Convertigo->Convertigo Project` and hit the `Next` button
2. In the dialog `Project remote URL` field, paste the text below:
   <table>
     <tr><td>Usage</td><td>Click the copy button</td></tr>
     <tr><td>To contribute</td><td>

     ```
     lib_OAuth=https://github.com/convertigo/c8oprj-lib-oauth.git:branch=8.0.0
     ```
     </td></tr>
     <tr><td>To simply use</td><td>

     ```
     lib_OAuth=https://github.com/convertigo/c8oprj-lib-oauth/archive/8.0.0.zip
     ```
     </td></tr>
    </table>
3. Click the `Finish` button. This will automatically import the __lib_OAuth__ project


## Sequences

### checkAccessOpenID

Checks is a valid access token is held by the current users' session for AzureAD

This as to be called by client apps to decide whenever or not they have to display an OAuth login screen



### checkAccessToken

Checks is a valid access token is held by the current users' session for AzureAD

This as to be called by client apps to decide whenever or not they have to display an OAuth login screen



### checkAccessTokenGoogle

Checks is a valid access token is held by the current users' session for Google

This as to be called by client apps to decide whenever or not they have to display an OAuth login screen



### checkAccessTokenLinkedIn

Checks is a valid access token is held by the current users' session for LinkedIn

This as to be called by client apps to decide whenever or not they have to display an OAuth login screen



### GetOAuthCredentials

Returns to the client the public OAuth credentials

### loginAzureAdWithAccessToken

Perform the OAuth flow for AzureAD

If the token is valid, it will be stored in the user's session to be used when calling Microsoft APIs.

Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>access_token</td><td></td>
</tr>
</table>

### loginGoogleWithCode

Perform the OAuth flow for Google

If the token is valid, it will be stored in the user's session to be used when calling Microsoft APIs.

Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>client_id</td><td></td>
</tr>
<tr>
<td>code</td><td></td>
</tr>
<tr>
<td>keySecret</td><td></td>
</tr>
<tr>
<td>redirect_uri</td><td></td>
</tr>
</table>

### loginLinkedInWithCode

Perform the OAuth flow for LinkedIn

If the token is valid, it will be stored in the user's session to be used when calling Microsoft APIs.

Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>client_id</td><td></td>
</tr>
<tr>
<td>code</td><td></td>
</tr>
<tr>
<td>keySecret</td><td></td>
</tr>
<tr>
<td>redirect_uri</td><td></td>
</tr>
</table>

### SignOut

Sign out from App.. Warning must be called with disableAutologin to true !



