using System;
using System.Collections.Generic;

namespace Apple.Auth.Signin.Models
{
  public class AccessTokenResponse
  {
    public string access_token { get; set; }
    public long expires_in { get; set; }
    public string id_token { get; set; }
    public string refresh_token { get; set; }
    public string token_type { get; set; }

    public string error { get; set; }
  }
}
