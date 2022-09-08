


# lib_OAuth

OAuth/OpenID library to perform authentication.
This library works in Conjunction with the Ngx Client Action [OAuth/OpenID](https://doc.convertigo.com/documentation/latest/reference-manual/convertigo-objects/mobile-application/components/action-components/oauth-openid)

## Symbols
OAuth works in conjunction with applications declared in the providers API portals. Please refer to the documentation fo each provider for details. When you declare an application, the portal will provide you with various IDs you will be able to configure in the following symbols.

|Symbol    | Comment           |
|----------|-------------------|
|lib_oauth.google.clientid    | The Google client id of your registered app on Google API portal           |
|lib_oauth.google.keysecret.secret    | The Google secret key of your registered app           |
|lib_oauth.azuread.clientid    | The Azure client id of your registered app on Microsoft Application Registration Portal (https://apps.dev.microsoft.com)    |
|lib_oauth.azuread.tenantid    | The optional Azure tenant id you will find in the same portal           |
|lib_oauth.linkedin.clientid    | The linkedIn client id you will find the LinkedIn API portal (https://www.linkedin.com/secure/developer?newapp           |
|lib_oauth.linkedin.keysecret.secret    | The linkedIn secret key you will find in the same portal           |

Here is how to set up the project for the different login providers:
- **Google**
    1. Log in to https://console.developers.google.com
    2. Create a **NEW PROJECT**.
    3. Go to **Credentials > Create credentials > OAuth client ID**
    4. Select **Web application**
    5. Choose a name for your *OAuth client ID*
    6. Add **Authorised JavaScript origins** like:
        - http://localhost:18080 for testing with your local Studio
        - https://c8ocloud.convertigo.net
    7. Add following **Authorised redirect URIs**:
        - https://c8ocloud.convertigo.net/convertigo/projects/libOAuth/getTokenGoogle.html
        

- **LinkedIn**
    1. Log in to https://linkedin.com/developers
    2. Go to **My Apps > Create app**
    3. Fill in the form to create your application.
    4. Go to **Auth > Application credentials**
        - Copy **Client ID** and **Client Secret** keys to Convertigo Symbols
    5. Go to **Auth > OAuth 2.0 settings** and set Redirect URLs:
        - https://c8ocloud.convertigo.net/convertigo/projects/libOAuth/getTokenlinkedIn.html

- **Azure**
    1. Log in to https://portal.azure.com
    2. Go to **All Services > Azure Active Directory > App registrations**
    3. Click **New registration**.
        - Choose a name.
        - In **Supported account types**, select Single or Multi tenant.
        - In **Redirect URI (optional)**, select **Public client/native**
        - Type in https://c8ocloud.convertigo.net/convertigo/projects/libOAuth/getToken.html
        - Click **Register**
    4. Click your project name:
        - Go to **Authentication > Advanced settings** and check **Access tokens** and **ID tokens**
        - Copy **Application (client) ID** and **Directory (tenant) ID** keys to Convertigo Symbols
        
        


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

This has to be called by client apps to decide whenever or not they have to display an OAuth login screen



### checkAccessToken

Checks is a valid access token is held by the current users' session for AzureAD

This has to be called by client apps to decide whenever or not they have to display an OAuth login screen



### checkAccessTokenGoogle

Checks is a valid access token is held by the current users' session for Google

This has to be called by client apps to decide whenever or not they have to display an OAuth login screen



### checkAccessTokenLinkedIn

Checks is a valid access token is held by the current users' session for LinkedIn

This as to be called by client apps to decide whenever or not they have to display an OAuth login screen



### GetOAuthCredentials

Returns to the client the public OAuth credentials

### loginAzureAdWithAccessToken

Perform the Backend OAuth flow for AzureAD

If the token is valid, it will be stored in the user's session to be used when calling Microsoft APIs. Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>access_token</td><td>The Access Token</td>
</tr>
</table>

### loginGoogleWithCode

Perform the Backend OAuth flow for Google

If the token is valid, it will be stored in the user's session to be used when calling Google APIs. Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>client_id</td><td>The Client ID provided by a symbol. (This is never provided by the client)</td>
</tr>
<tr>
<td>code</td><td>The OAuth CODE provided by the client</td>
</tr>
<tr>
<td>keySecret</td><td>The OAuth secret key provided by a Symbol (This is never provided by the client)</td>
</tr>
<tr>
<td>redirect_uri</td><td>The Google OAuth redirect as configured in the Google Application registration</td>
</tr>
</table>

### loginLinkedInWithCode

Perform the OAuth flow for LinkedIn

If the token is valid, it will be stored in the user's session to be used when calling LinkedIn APIs. Also if the token is valid, setAuthenticatedUser step is executed to flag this session as authenticated.


**variables**

<table>
<tr>
<th>name</th><th>comment</th>
</tr>
<tr>
<td>client_id</td><td>The Client ID provided by a symbol. (This is never provided by the client)</td>
</tr>
<tr>
<td>code</td><td>The OAuth CODE provided by the client</td>
</tr>
<tr>
<td>keySecret</td><td>The OAuth secret key provided by a Symbol (This is never provided by the client)</td>
</tr>
<tr>
<td>redirect_uri</td><td>The LinkedIn OAuth redirect as configured in the Google Application registration</td>
</tr>
</table>

### SignOut

Sign out from App.. Warning must be called with disableAutologin to true !



