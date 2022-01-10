namespace OMS.Identity.Services;

public class CaptchaRequest
{
    public CaptchaRequest(Guid id, string code, string base64Image)
    {
        Id = id;
        Code = code;
        Base64Image = base64Image;
    }

    public Guid Id { get; set; }
    public string Code { get; set; }
    public string Base64Image { get; set; }
}