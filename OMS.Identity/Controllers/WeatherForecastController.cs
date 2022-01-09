using Microsoft.AspNetCore.Mvc;
using OMS.Identity.Services;

namespace OMS.Identity.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;
    private readonly IAuthService _authService;

    public WeatherForecastController(ILogger<WeatherForecastController> logger, IAuthService authService)
    {
        _logger = logger;
        _authService = authService;
    }

    [HttpGet(Name = "GetWeatherForecast")]
    public async Task<IEnumerable<WeatherForecast>> Get()
    {
        var code = await _authService.Login("aref", "abcd");
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
    }
    
    [HttpPost]
    public async Task<AuthenticationReply> Post(string code)
    {
        return await _authService.VerifyCode("aref",code);
    }
}