using Microsoft.AspNetCore.Identity;

namespace OMS.Identity.Infrastructure.Entities;

public class ApplicationUser : IdentityUser<Guid>
{
    public ApplicationUser() : base()
    {
        Id = Guid.NewGuid();
    }
}