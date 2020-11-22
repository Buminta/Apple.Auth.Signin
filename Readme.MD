# Apple.Auth.Signin
dotnet core for simple Apple Auth Signin
> Simple for use
> Worker with Dotnet core 2.x or 3.x
> Exactly work in Unix/Linux/Ubuntu/Debian/Centos OS

[![NuGet](https://img.shields.io/badge/nuget-v1.0.1-blue)](https://www.nuget.org/packages/Apple.Auth.Signin/)

# What is AppleAuth.NET?
AppleAuth is a very simple library for .NET that encapsulates the logic for communicating with [Apple's REST API for Sign in with Apple](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api).
The main goal is to make the implementation of [Sign in with Apple](https://developer.apple.com/sign-in-with-apple/) easier for any web application.

# How to use it?
## Installation
To install the package execute the following command in your Package Manager Console:
```javascript
PM> Install-Package Apple.Auth.Signin
```
Or alternatively just install the package using Nuget package manager. The project can be found here:
[Link to NuGet](https://www.nuget.org/packages/Apple.Auth.Signin/)

# Prerequisites
## Configure Sign in with Apple from the Developer Portal
In order to use Sign in with Apple you must enroll in the [Apple Developer Program](https://developer.apple.com/programs/enroll/).
After you have enrolled in the program go to [Developer Account Help](https://help.apple.com/developer-account/) and navigate to Configure app capabilities > Sign in with Apple.
There you can find the information for configuring Sign in with Apple for your app.

```c#
    // Get Your client_secret with 5 minutes exp.
    // Method GetClientSecret(string teamId, string keyId, string clientId, string authKeyPath, int expAt = 5);
    var clientSecret = Apple.Auth.Sigin.Token.GetClientSecret("teamId", "keyId", "clientId", "authKeyPath.p8");

    // Get Your client_secret with custom one hour exp.
    var clientSecret = Apple.Auth.Sigin.Token.GetClientSecret("teamId", "keyId", "clientId", "authKeyPath.p8", 60);

    // Get Access token for verify client signin
    // Method GetAccessToken(string clientId, string clientSecret, string grantType = "authorization_code|refresh_token", string code = null, string refreshToken = null, string redirectUri = null);
    var appleRes = await Apple.Auth.Sigin.Token.GetAccessToken("clientId", clientSecret, "authorization_code", "yourClientCode");

    // Reresh access token
    var appleRes = await Token.GetAccessToken("clientId", clientSecret, "refresh_token", null, "refreshToken");
```
# Contributing

You are more than welcome to contribute to the project and make it better. When contributing please try to maintain a strictly professional, respectful and friendly attitude. Also make sure you communicate the change you want to make via issue or any other method with the owners of this repository.
