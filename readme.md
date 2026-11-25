


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
|lib_oauth.openid.issuer	| Optional. The OpenID issuer URL used to verify access tokens (defaults to the iss of the introspection response) |
|lib_oauth.openid.audience	| Optional. Comma separated access token audiences accepted besides the OpenID client id |
|lib_oauth.callback.allowed_origins	| Optional. Comma separated origins (https://host[:port]) of the applications of other servers allowed to receive the answer of the callback pages; the applications of this server are always allowed |
|lib_oauth.openid.scope	| Optional. Scopes requested by the OpenID sign-in, separated by spaces or commas (default `openid profile email`; `openid` is always requested) |
|lib_oauth.openid.groups_claim	| Optional. Claim that holds the groups of an OpenID user (for example `groups`, `roles` or `realm_access.roles`); empty: the groups are not read |

## Token verification

JWT are verified by *js/jwt_verify.js* before any claim is used: signature (RS256/ES256 family, keys from the provider JWKS found by OpenID discovery and cached), issuer, audience (the configured client id), exp / nbf / iat with 5 minutes of clock skew. Tokens with alg none or HS* are refused.

The client ids lib_oauth.google.clientid, lib_oauth.azuread.clientid and lib_oauth.openid.clientid must be defined on the server for the Google, Microsoft and OpenID sign-ins: the tokens are checked against them, and the sign-in is refused when the symbol is not defined.

- *loginGoogleWithCode*: the id_token returned by the token endpoint must be issued by Google for lib_oauth.google.clientid.
- *loginAzureAdWithAccessToken*: the id_token sent with the access token is required. It must be issued for lib_oauth.azuread.clientid by lib_oauth.azuread.tenantid (common / organizations accept any tenant) and its at_hash must match the access token.
- *loginOpenIDWithAccessToken*: the introspection response is authoritative: active, sub, exp / nbf when present, iss equal to lib_oauth.openid.issuer when both are known.
    - opaque access token: the introspection client_id or aud must contain lib_oauth.openid.clientid (or a lib_oauth.openid.audience value); the claims are the introspection response.
    - JWT access token: also signed by the issuer (discovery of lib_oauth.openid.issuer, or of the introspection iss) and issued for the client id (aud, azp, client_id or cid claim, or introspection client_id / aud).
    - Microsoft Entra (issuer login.microsoftonline.com / sts.windows.net, or a nonce in the access token header as in Graph tokens, which only Microsoft can verify): the id_token variable is verified instead (issuer, aud = client id, at_hash of the access token, sub equal to the introspected sub); without id_token the opaque token rules apply.

## OpenID scopes and groups

*GetOAuthCredentials* returns `OpenIDScope`: the scopes of lib_oauth.openid.scope, URL encoded for the scope of the OAuth action, which adds it to the authorization URL as it is. Without the symbol it is `openid%20profile%20email`, the scopes of the earlier versions. An invalid value (a character that RFC 6749 does not allow in a scope, more than 50 scopes) is ignored with a warning in the logs.

When lib_oauth.openid.groups_claim names a claim, *loginOpenIDWithAccessToken* reads the groups of the user from verified sources only, in this order; the first one that holds the claim decides.

1. the id_token sent with the access token, verified like the Microsoft one: signature with the JWKS of the issuer, issuer, audience (client id), dates, at_hash of the access token, sub of the introspection response;
2. the verified JWT access token, or the introspection response;
3. the userinfo endpoint of the discovery document of the issuer (https only), called with the access token; its sub must be the sub of the user.

A string is one group, a list of strings is the list of groups (trimmed, duplicates removed, names with control characters or longer than 256 characters ignored). Any other value, or more than 200 groups, counts as no group. When no source holds the claim, the user has no group. A claim name with dots that is not a claim of its own is a path in nested claims (`realm_access.roles`).

The groups are never taken from the client: they are kept on the server, in the session key `oAuthOpenIDGroups` (removed by *SignOut*, and at each sign-in when the symbol is empty): a JSON object `{user, claim, state, groups, source, at}` where `user` is the authenticated user they belong to and `state` is `present` or `missing`. The application decides what the groups give (C8Oforms puts the user in lib_FullSyncGrp groups); this library never grants anything from them. Neither the tokens nor the groups are written in the logs.

## Callback pages

The callback pages *getToken.html* (Microsoft, OpenID), *getTokenGoogle.html* and *getTokenLinkedIn.html* give the answer of the provider (access token and id_token, or authorization code) to the window that opened the sign-in popup. They post it only to the origin of this server and to the origins of lib_oauth.callback.allowed_origins (read by the *getCallbackOrigins* sequence, see *js/oauth_callback.js*).

An application served by another server that uses the callback of this server (as C8Oforms with the c8ocloud callback) needs its exact origin in lib_oauth.callback.allowed_origins, for example `https://forms.example.com, http://localhost:18080`. `*`, paths and patterns are ignored.

## Best Practices

Client secrets must never be embedded in the client applications. The best way to use them in the *OAuth* Action is to call the *GetOAuthCredentials* sequence to retrieve on the client side the necessary credentials.

## Configure the OAuth / OpenID providers

Follow the https://doc.convertigo.com/documentation/latest/reference-manual/convertigo-objects/mobile-application/components/action-components/oauth-openid instructions to learn on how to configure your OAuth IDP.



## Authentication Modes And Required Symbols

<a id="auth-mode-google"></a>
### Google Login (loginGoogleWithCode / checkAccessTokenGoogle)

| symbol                            | Required | Usage |
|-----------------------------------|----------|-------|
| lib_oauth.google.clientid         | yes      | Google OAuth client id returned by `GetOAuthCredentials`, used by `loginGoogleWithCode` and required as the id_token audience |
| lib_oauth.google.keysecret.secret | yes      | Google OAuth client secret sent as `keySecret` during code-to-token exchange |

<a id="auth-mode-microsoft"></a>
### Microsoft Login (loginAzureAdWithAccessToken / checkAccessToken)

| symbol                    | Required | Usage |
|---------------------------|----------|-------|
| lib_oauth.azuread.clientid | yes      | Azure AD app client id returned by `GetOAuthCredentials` for client-side OAuth, required as the id_token audience |
| lib_oauth.azuread.tenantid | yes      | Azure AD tenant id returned by `GetOAuthCredentials` and used to target the right authority; the id_token issuer must belong to this tenant (`common` / `organizations`: any tenant) |

`loginAzureAdWithAccessToken` requires the `id_token` returned with the access token (OAuth action with `response_type=id_token+token`, "ID tokens" enabled on the app registration).

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
| lib_oauth.openid.clientid             | yes      | OpenID client id returned by `GetOAuthCredentials`, required as the accepted audience of the tokens |
| lib_oauth.openid.endpoint             | yes      | OpenID provider endpoint returned by `GetOAuthCredentials` for client-side OAuth/OpenID actions |
| lib_oauth.openid.clientsecret.secret  | optional | OpenID client secret (required for providers/flows needing a confidential client) |
| lib_oauth.openid.instrospect_url      | yes      | Introspection endpoint used by `loginOpenIDWithAccessToken` |
| lib_oauth.openid.issuer               | optional | Issuer whose discovery document and JWKS verify the access token; defaults to the `iss` of the introspection response |
| lib_oauth.openid.audience             | optional | Comma separated access token audiences accepted besides `lib_oauth.openid.clientid` |
| lib_oauth.openid.scope                | optional | Scopes of the OpenID sign-in returned URL encoded by `GetOAuthCredentials` (`OpenIDScope`); default `openid profile email` |
| lib_oauth.openid.groups_claim         | optional | Claim holding the groups of the user, kept in the session key `oAuthOpenIDGroups` (see [OpenID scopes and groups](#openid-scopes-and-groups)); empty: no group read |

`redirect_uri` is sent by the client application and must match the redirect URI configured on each provider.



For more technical informations : [documentation](./project.md)

- [Installation](#installation)
- [Sequences](#sequences)
    - [checkAccessOpenID](#checkaccessopenid)
    - [checkAccessToken](#checkaccesstoken)
    - [checkAccessTokenGoogle](#checkaccesstokengoogle)
    - [checkAccessTokenLinkedIn](#checkaccesstokenlinkedin)
    - [getCallbackOrigins](#getcallbackorigins)
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
     lib_OAuth=https://github.com/convertigo/c8oprj-lib-oauth.git:branch=8.0.1
     ```
     </td></tr>
     <tr><td>To simply use</td><td>

     ```
     lib_OAuth=https://github.com/convertigo/c8oprj-lib-oauth/archive/8.0.1.zip
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



### getCallbackOrigins

Returns the origins allowed to receive the answer of an OAuth provider from the callback pages getToken.html, getTokenGoogle.html and getTokenLinkedIn.html besides the origin of this server (symbol lib_oauth.callback.allowed_origins, see js/oauth_callback.js)

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
<tr>
<td>id_token</td><td>The id_token returned with the access token by the OAuth action (response_type id_token+token). It is verified and must carry the at_hash of access_token.</td>
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
<td>id_token</td><td>The id_token returned with the access token (response_type id_token+token). Required to verify Microsoft Graph access tokens, which carry a nonce header; it must carry the at_hash of access_token.</td>
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


