namespace OMS.Identity.Infrastructure.Entities;
public class RefreshToken : BaseEntity
{
    public string Token { get; set; }
    public DateTime ExpirationDate { get; set; }
    public Guid UserId { get; set; }
    public string JWTId { get; set; }
    public bool Used { get; set; }
    public bool InValidation { get; internal set; }
}