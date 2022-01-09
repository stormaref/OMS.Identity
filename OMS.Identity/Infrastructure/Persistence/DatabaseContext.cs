using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using OMS.Identity.Infrastructure.Entities;

namespace OMS.Identity.Infrastructure.Persistence;

public class DatabaseContext : IdentityDbContext<ApplicationUser, IdentityRole<Guid>, Guid>
{
    public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

        base.OnModelCreating(builder);
    }

    public DbSet<RefreshToken> RefreshTokens { get; set; }
}

public class DatabaseContextFactory : IDesignTimeDbContextFactory<DatabaseContext>
{
    public DatabaseContext CreateDbContext(string[] args)
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddEnvironmentVariables()
            .AddJsonFile("appsettings.json")
            .Build();
        // Here we create the DbContextOptionsBuilder manually.        
        var builder = new DbContextOptionsBuilder<DatabaseContext>();

        // Build connection string. This requires that you have a connectionstring in the appsettings.json
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        builder.UseSqlServer(connectionString);
        // Create our DbContext.
        return new DatabaseContext(builder.Options);
    }
}