


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



## Authentication Modes And Required Symbols

<a id="auth-mode-google"></a>
### Google Login (loginGoogleWithCode / checkAccessTokenGoogle)

| symbol                            | Required | Usage |
|-----------------------------------|----------|-------|
| lib_oauth.google.clientid         | yes      | Google OAuth client id returned by `GetOAuthCredentials` and used by `loginGoogleWithCode` |
| lib_oauth.google.keysecret.secret | yes      | Google OAuth client secret sent as `keySecret` during code-to-token exchange |

<a id="auth-mode-microsoft"></a>
### Microsoft Login (loginAzureAdWithAccessToken / checkAccessToken)

| symbol                    | Required | Usage |
|---------------------------|----------|-------|
| lib_oauth.azuread.clientid | yes      | Azure AD app client id returned by `GetOAuthCredentials` for client-side OAuth |
| lib_oauth.azuread.tenantid | yes      | Azure AD tenant id returned by `GetOAuthCredentials` and used to target the right authority |

<a id="auth-mode-linkedin"></a>
### LinkedIn Login (loginLinkedInWithCode / checkAccessTokenLinkedIn)

| symbol                              | Required | Usage |
|-------------------------------------|----------|-------|
| lib_oauth.linkedin.clientid         | yes      | LinkedIn OAuth client id returned by `GetOAuthCredentials` and used by `loginLinkedInWithCode` |
| lib_oauth.linkedin.keysecret.secret | yes      | LinkedIn OAuth client secret sent as `keySecret` during code-to-token exchange |

<a id="auth-mode-github"></a>
### GitHub Login (loginGitHubWithCode)

| symbol                            | Required | Usage |
|-----------------------------------|----------|-------|
| lib_oauth.github.clientid         | yes      | GitHub OAuth client id returned by `GetOAuthCredentials` and used by `loginGitHubWithCode` |
| lib_oauth.github.keysecret.secret | yes      | GitHub OAuth client secret sent as `keySecret` during code-to-token exchange |

<a id="auth-mode-openid"></a>
### OpenID Login (loginOpenIDWithAccessToken / checkAccessOpenID)

| symbol                                | Required | Usage |
|---------------------------------------|----------|-------|
| lib_oauth.openid.clientid             | yes      | OpenID client id returned by `GetOAuthCredentials` |
| lib_oauth.openid.endpoint             | yes      | OpenID provider endpoint returned by `GetOAuthCredentials` for client-side OAuth/OpenID actions |
| lib_oauth.openid.clientsecret.secret  | optional | OpenID client secret (required for providers/flows needing a confidential client) |
| lib_oauth.openid.instrospect_url      | yes      | Introspection endpoint used by `loginOpenIDWithAccessToken` (`introspectURL` variable default) |

`redirect_uri` is sent by the client application and must match the redirect URI configured on each provider.



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


