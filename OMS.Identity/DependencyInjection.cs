using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OMS.Identity.Common.Extensions;
using OMS.Identity.Common.Settings;
using OMS.Identity.Infrastructure.Entities;
using OMS.Identity.Infrastructure.Persistence;
using OMS.Identity.Services;

namespace OMS.Identity;

public static class DependencyInjection
{
    public static void AddServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<DataProtectionTokenProviderOptions>(
            x => x.TokenLifespan = TimeSpan.FromMinutes(5));

        services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(config =>
            {
                config.Password.RequiredLength = 6;
                config.Password.RequireDigit = false;
                config.Password.RequireNonAlphanumeric = false;
                config.Password.RequireUppercase = false;
                config.SignIn.RequireConfirmedEmail = false;
                config.Password.RequireLowercase = false;
                config.SignIn.RequireConfirmedPhoneNumber = true;
            })
            .AddEntityFrameworkStores<DatabaseContext>()
            .AddDefaultTokenProviders()
            .AddOTPAuthenticateTokenProvider();

        TokenValidationParameters tokenValidationParameters = new()
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidIssuer = configuration["JWTKeys:Issuer"],
            ClockSkew = TimeSpan.Zero,
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTKeys:SigningKey"]))
        };

        services.Configure<JWTKeys>(configuration.GetSection("JWTKeys"));

        services.AddDbContext<DatabaseContext>(options =>
            options.UseSqlServer(
                    configuration.GetConnectionString("DefaultConnection"),
                    b => b.MigrationsAssembly(typeof(DatabaseContext).Assembly.FullName))
                .EnableSensitiveDataLogging()
        );

        services.AddScoped<IAuthService, AuthService>();
    }
}