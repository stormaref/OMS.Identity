using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OMS.Identity.Common.Settings;
using OMS.Identity.Common.Tools;
using OMS.Identity.Infrastructure.Entities;
using OMS.Identity.Infrastructure.Persistence;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace OMS.Identity.Services;

public interface IAuthService
{
    Task<string> Login(string username, string password);
    Task<AuthenticationReply> VerifyCode(string username, string code);
    Task<AuthenticationReply> RefreshTokenAsync(RefreshTokenRequest refreshToken);
    Task<CaptchaRequest> RequestCaptcha(Guid? id);
}

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
    private readonly ICacheService _cacheService;
    private readonly DatabaseContext _context;
    private readonly JWTKeys _jwtKeys;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        DatabaseContext context,
        IOptionsSnapshot<JWTKeys> options,
        ICacheService cacheService)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
        _cacheService = cacheService;
        _jwtKeys = options.Value;
    }

    public async Task<CaptchaRequest> RequestCaptcha(Guid? id)
    {
        if (id is null)
        {
            id = Guid.NewGuid();
        }
        else
        {
            var captchaRequest = await _cacheService.GetFromCache<CaptchaRequest>(id.ToString());
            if (captchaRequest == null)
            {
                //todo exception
            }
        }

        var (code, captcha) = CaptchaCreator.Create();
        var request = new CaptchaRequest(id.Value, code, captcha);
        await _cacheService.SetCache(
            id.Value.ToString(),
            request,
            new DistributedCacheEntryOptions()
            {
                AbsoluteExpiration = DateTimeOffset.Now.AddSeconds(30)
            });

        return request;
    }

    public async Task<string> Login(string username, string password)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
        {
            await RegisterNewUser(username, password);
            return "";
        }

        var isValid = await _userManager.CheckPasswordAsync(user, password);
        if (!isValid)
        {
            return "";
        }

        var code = await _userManager.GenerateTwoFactorTokenAsync(user, ConstantStrings.TokenProvider);
        return code;
        //todo send code
    }

    private async Task RegisterNewUser(string username, string password)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user is not null)
        {
            //todo
        }

        var applicationUser = new ApplicationUser()
        {
            UserName = username,
            TwoFactorEnabled = true,
        };
        applicationUser.PasswordHash = _userManager.PasswordHasher.HashPassword(applicationUser, password);
        await _userManager.CreateAsync(applicationUser);
    }

    public async Task<AuthenticationReply> VerifyCode(string username, string code)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user is null)
            return GetErrorReply("User not found");
        var isValid =
            await _userManager.VerifyTwoFactorTokenAsync(user, ConstantStrings.TokenProvider, code);
        if (!isValid)
            return GetErrorReply("Code is not valid");
        var token = await GenerateToken(user);
        return token;
    }

    private AuthenticationReply GetErrorReply(string error)
    {
        var reply = new AuthenticationReply {Succeeded = false};
        reply.Errors.Add(error);
        return reply;
    }

    public async Task<AuthenticationReply> RefreshTokenAsync(RefreshTokenRequest refreshToken)
    {
        ClaimsPrincipal validateToken = GetPrincipalFromToken(refreshToken.Token);

        if (validateToken == null)
            return GetRefreshTokenResult("Invalid token", "توکن نامعتبر است");

        long expiryDateUnix =
            long.Parse(validateToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

        DateTime expiryDateTimeUtc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(expiryDateUnix);

        if (expiryDateTimeUtc > DateTime.UtcNow)
            return GetRefreshTokenResult("token is not expired", "توکن انقضا نشده است");

        string jti = validateToken.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

        RefreshToken storeRefreshToken =
            await _context.RefreshTokens.SingleOrDefaultAsync(x => x.Token == refreshToken.RefreshToken);

        if (storeRefreshToken == null)
            return GetRefreshTokenResult("This refresh token does not exist", "توکن بازیابی وجود ندارد");

        if (storeRefreshToken.Used)
            return GetRefreshTokenResult("Token is used ", "توکن استفاده شده است");

        if (DateTime.UtcNow > storeRefreshToken.ExpirationDate)
            return GetRefreshTokenResult("refresh token is expired", "توکن بازیابی انقضا شده است");

        if (storeRefreshToken.InValidation)
            return GetRefreshTokenResult("This refresh token has been invalidated", "توکن بازیابی نامعتبر است");

        if (storeRefreshToken.JWTId != jti)
            return GetRefreshTokenResult("This refresh token does not match this JWT", "توکن بازیابی نادرست است");

        storeRefreshToken.Used = true;

        _context.RefreshTokens.Update(storeRefreshToken);
        await _context.SaveChangesAsync();

        ApplicationUser user =
            await _userManager.FindByIdAsync(validateToken.Claims.Single(x => x.Type == "UserId").Value);

        return await GenerateToken(user);
    }

    private async Task<AuthenticationReply> GenerateToken(ApplicationUser user)
    {
        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        byte[] key = Encoding.UTF8.GetBytes(_jwtKeys.SigningKey);
        //string audience = _jwtKeys.Value.Audiences[1];
        string issuer = _jwtKeys.Issuer;
        int expiryInMinutes = Convert.ToInt32(_jwtKeys.ExpiryInMinutes);

        //var roles = await _userManager.GetRolesAsync(user);

        List<Claim> claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.UserName),
            //new Claim(ClaimTypes.Role, string.Join(",", roles)),
            //new Claim("Name", user.UserName ??= ""),
        };

        var userClaims = await _userManager.GetClaimsAsync(user);

        claims.AddRange(userClaims);

        var userRoles = await _userManager.GetRolesAsync(user);

        foreach (string userRole in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, userRole));

            var role = await _roleManager.FindByNameAsync(userRole);

            IList<Claim> roleClaims = await _roleManager.GetClaimsAsync(role);

            foreach (Claim roleClaim in roleClaims)
            {
                claims.Add(roleClaim);
            }
        }

        SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            //Audience = audience,
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(expiryInMinutes),
            SigningCredentials =
                new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        };

        SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);

        RefreshToken refreshToken = new RefreshToken()
        {
            Token = Guid.NewGuid().ToString(),
            JWTId = token.Id,
            UserId = user.Id,
            CreationDate = DateTime.UtcNow,
            ExpirationDate = DateTime.UtcNow.AddMonths(6)
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();

        return new AuthenticationReply
        {
            Succeeded = true,
            RefreshToken = refreshToken.Token,
            Token = tokenHandler.WriteToken(token),
            Username = user.UserName
        };
    }

    private ClaimsPrincipal GetPrincipalFromToken(string token)
    {
        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

        byte[] key = Encoding.UTF8.GetBytes(_jwtKeys.SigningKey);

        TokenValidationParameters tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            //ValidAudiences = _jwtKeys.Value.Audiences,
            ValidIssuer = _jwtKeys.Issuer,
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = false
        };

        try
        {
            ClaimsPrincipal principle =
                tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validateToken);

            if (!IsJwtWithValidSecurityAlgorithm(validateToken))
                return null;

            return principle;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private bool IsJwtWithValidSecurityAlgorithm(SecurityToken validToken)
    {
        return (validToken is JwtSecurityToken jwtSecurityToken) &&
               jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                   StringComparison.InvariantCultureIgnoreCase);
    }

    private AuthenticationReply GetRefreshTokenResult(string enError, string exceptionMessage)
    {
        var reply = new AuthenticationReply {Succeeded = false};
        reply.Exceptions.Add(exceptionMessage);
        reply.Errors.Add(enError);
        return reply;
    }
}

public class ConstantStrings
{
    public const string TokenProvider = "OTPAuthenticateTokenProvider";
}

public class RefreshTokenRequest
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}

public class AuthenticationReply
{
    public AuthenticationReply()
    {
        Exceptions = new List<string>();
        Errors = new List<string>();
    }

    public bool Succeeded { get; set; }
    public List<string> Exceptions { get; set; }
    public List<string> Errors { get; set; }
    public string RefreshToken { get; set; }
    public string Token { get; set; }
    public string Username { get; set; }
}