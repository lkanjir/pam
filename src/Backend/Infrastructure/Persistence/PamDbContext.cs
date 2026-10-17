using Domain;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Persistence;

public class PamDbContext : DbContext
{
    public PamDbContext(DbContextOptions<PamDbContext> options) : base(options)
    {
    }

    public DbSet<Principal> Principals => Set<Principal>();
    public DbSet<AuthenticationSessionLedger> AuthenticationSessionLedgers => Set<AuthenticationSessionLedger>();
    public DbSet<PamRole> PamRoles => Set<PamRole>();
    public DbSet<PamRoleAssignment> PamRoleAssignments => Set<PamRoleAssignment>();
    public DbSet<ManagedResource> ManagedResources => Set<ManagedResource>();
    public DbSet<Entitlement> Entitlements => Set<Entitlement>();
    public DbSet<EligibilityRule> EligibilityRules => Set<EligibilityRule>();
    public DbSet<AccessRequest> AccessRequests => Set<AccessRequest>();
    public DbSet<PolicyEvaluation>  PolicyEvaluations => Set<PolicyEvaluation>();
    public DbSet<AuditEvent>  AuditEvents => Set<AuditEvent>();
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(PamDbContext).Assembly);
    }
}