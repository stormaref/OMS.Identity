namespace OMS.Identity.Common.Settings;

public class JWTKeys
{
    public string[] Audiences { get; set; }
    public string Issuer { get; set; }
    public string SigningKey { get; set; }
    public string ExpiryInMinutes { get; set; }
}