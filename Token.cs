using System;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Apple.Auth.Signin.Models;
using System.Security.Cryptography;
using System.Net.Http;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using Apple.Auth.Signin.Constants;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Apple.Auth.Signin
{
    public static class Token
    {
        public static async Task<AccessTokenResponse> GetAccessToken(string clientId, string clientSecret, string grantType = "authorization_code", string code = null, string refreshToken = null, string redirectUri = null){
          var verifyTokenEndPoint = $"https://appleid.apple.com/auth/token?client_id={clientId}&client_secret={clientSecret}&grant_type={grantType}";
          
          if(grantType == "refresh_token")
          {
            verifyTokenEndPoint += $"&refresh_token={refreshToken}";
          }
          else
          {
            verifyTokenEndPoint += $"&code={code}";
          }

          if(!String.IsNullOrEmpty(redirectUri))
          {
            verifyTokenEndPoint += $"&redirect_uri={redirectUri}";
          }

          var client = new HttpClient();
          var uri = new Uri(verifyTokenEndPoint);

          var response = await client.PostAsync(uri, null);
          var content = await response.Content.ReadAsStringAsync();
          return JsonConvert.DeserializeObject<AccessTokenResponse>(content);
        }

        public static string GetClientSecret(string teamId, string keyId, string clientId, string authKeyPath, int expAt = 5)
        {
            var dsa = GetECDsa(authKeyPath);
            return CreateJwt(dsa, keyId, clientId, teamId, expAt);
        }
        
        private static ECDsa GetECDsa(string authKeyPath)
        {
            using (TextReader reader = System.IO.File.OpenText(authKeyPath))
            {
              var ecPrivateKeyParameters =
                  (ECPrivateKeyParameters) new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();

              var q = ecPrivateKeyParameters.Parameters.G.Multiply(ecPrivateKeyParameters.D).Normalize();
              var qx = q.AffineXCoord.GetEncoded();
              var qy = q.AffineYCoord.GetEncoded();
              var d = ecPrivateKeyParameters.D.ToByteArrayUnsigned();

              // Convert the BouncyCastle key to a Native Key.
              var msEcp = new ECParameters {Curve = ECCurve.NamedCurves.nistP256, Q = {X = qx, Y = qy}, D = d};
              return ECDsa.Create(msEcp);
            }
        }
        
        private static string CreateJwt(ECDsa key, string keyId, string clientId, string teamId, int expAt = 5)
        {
            var signingCredentials = new SigningCredentials(
            new ECDsaSecurityKey(key), SecurityAlgorithms.EcdsaSha256);

            var now = DateTime.UtcNow;

            var claims = new List<Claim>
            {
                new Claim(ClaimConstants.Issuer, teamId),
                new Claim(ClaimConstants.IssuedAt, EpochTime.GetIntDate(now).ToString(), ClaimValueTypes.Integer64),
                new Claim(ClaimConstants.Expiration, EpochTime.GetIntDate(now.AddMinutes(5)).ToString(), ClaimValueTypes.Integer64),
                new Claim(ClaimConstants.Audience, "https://appleid.apple.com"),
                new Claim(ClaimConstants.Sub, clientId)
            };

            var tokenJWT = new JwtSecurityToken(
                issuer: teamId,
                claims: claims,
                expires: now.AddMinutes(expAt),
                signingCredentials: signingCredentials
            );

            tokenJWT.Header.Add(ClaimConstants.KeyID, keyId);
            JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();
            return _tokenHandler.WriteToken(tokenJWT);
        }
    }
}
