using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace OMS.Identity.Services;

public interface ICacheService
{
    Task<T?> GetFromCache<T>(string key) where T : class;
    Task RemoveCache(string key);
    Task SetCache<T>(string key, T value, DistributedCacheEntryOptions options) where T : class;
}

public class CacheService : ICacheService
{
    private readonly IDistributedCache _distributedCache;
    private readonly ILogger<CacheService> _logger;

    public CacheService(ILogger<CacheService> logger, IDistributedCache distributedCache)
    {
        _logger = logger;
        _distributedCache = distributedCache;
    }

    public async Task<T?> GetFromCache<T>(string key) where T : class
    {
        try
        {
            var cachedResponse = await _distributedCache.GetStringAsync(key);
            return cachedResponse == null ? null : JsonSerializer.Deserialize<T>(cachedResponse);
        }
        catch (Exception exp)
        {
            _logger.LogError(exp.Message, exp);
            return null;
        }
    }

    public async Task SetCache<T>(string key, T value, DistributedCacheEntryOptions options) where T : class
    {
        var response = JsonSerializer.Serialize(value);
        await _distributedCache.SetStringAsync(key, response, options);
    }

    public async Task RemoveCache(string key)
    {
        await _distributedCache.RemoveAsync(key);
    }
}