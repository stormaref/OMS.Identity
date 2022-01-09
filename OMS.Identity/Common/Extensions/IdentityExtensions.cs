using Microsoft.AspNetCore.Identity;
using OMS.Identity.Services;

namespace OMS.Identity.Common.Extensions;

public static class IdentityExtensions
{
    public static IdentityBuilder AddOTPAuthenticateTokenProvider(this IdentityBuilder builder)
    {
        var userType = builder.UserType;
        var type = typeof(CustomTokenProvider<>).MakeGenericType(userType);
        return builder.AddTokenProvider(ConstantStrings.TokenProvider, type);
    }
}

public class CustomTokenProvider<TUser> : TotpSecurityStampBasedTokenProvider<TUser>
    where TUser : class
{
    public override Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> manager, TUser user)
    {
        return Task.FromResult(false);
    }
}