


# lib_OAuth

# OAuth library to perform authentication
This is the OAuth Library for Convertigo applications. This library is used in conjunction with the [OAuth](https://doc.convertigo.com/documentation/latest/reference-manual/convertigo-objects/mobile-application/components/action-components/oauth-openid) Action to perform SSO Login to Convertigo Apps.

## Symbols

| Symbol                     | Usaqe                                           |
|----------------------------|-------------------------------------------------|
|lib_oauth.azuread.clientid	| The Azure Active Directory Client ID             |
|lib_oauth.azuread.tenantid	| The Azure Active Directory Tenant ID             |
|lib_oauth.github.clientid	| The GitHub Client ID                             |
|lib_oauth.github.keysecret.secret	| The Azure Active Directory Client Secret |
|lib_oauth.google.clientid	| The Google Client ID                             |
|lib_oauth.google.keysecret.secret	| The Azure Active Directory Client Secret |
|lib_oauth.linkedin.clientid	| The LinkedIn Client ID                           |
|lib_oauth.linkedin.keysecret.secret	| The LinkedIn Client Secret               |
|lib_oauth.openid.clientid	| The Openid Client id                             |
|lib_oauth.openid.clientsecret.secret	| The Openid Client Secret             |
|lib_oauth.openid.introspect_url	| The Openid introspect API endpoint URL       |

## Best Practices

Client secrets must never be embedded in the client applications. The best way to use them in the *OAuth* Action is to call the *GetOAuthCredentials* sequence to retrieve on the client side the necessary credentials.

## Configure the OAuth / OpenID providers

Follow the https://doc.convertigo.com/documentation/latest/reference-manual/convertigo-objects/mobile-application/components/action-components/oauth-openid instructions to learn on how to configure your OAuth IDP.




For more technical informations : [documentation](./project.md)

- [Installation](#installation)
- [Sequences](#sequences)
    - [checkAccessOpenID](#checkaccessopenid)
    - [checkAccessToken](#checkaccesstoken)
    - [checkAccessTokenGoogle](#checkaccesstokengoogle)
    - [checkAccessTokenLinkedIn](#checkaccesstokenlinkedin)
    - [GetOAuthCredentials](#getoauthcredentials)
    - [listGroupsAzureAd](#listgroupsazuread)
    - [loginAzureAdWithAccessToken](#loginazureadwithaccesstoken)
    - [loginGitHubWithCode](#logingithubwithcode)
    - [loginGoogleWithCode](#logingooglewithcode)
    - [loginLinkedInWithCode](#loginlinkedinwithcode)
    - [loginOpenIDWithAccessToken](#loginopenidwithaccesstoken)
    - [setLastConnected](#setlastconnected)
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

### listGroupsAzureAd

Returns the list of groups for a user for AzureAD

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

### loginGitHubWithCode

Perform the OAuth flow for GitHub with Code

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

### loginOpenIDWithAccessToken

Perform the OAuth flow for OpenID with a JWT acess token

If the token is valid, it will be stored in the user's session

Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.



**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>access_token</td><td>The JWT acess Token</td>
</tr>
<tr>
<td>introspectURL</td><td>The URL to call to instrospect and validate the TWT token</td>
</tr>
</table>

### setLastConnected

Sets a lastConnected timestamp in the user database

**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>user</td><td></td>
</tr>
</table>

### SignOut

Sign out from App.. Warning must be called with disableAutologin to true !



