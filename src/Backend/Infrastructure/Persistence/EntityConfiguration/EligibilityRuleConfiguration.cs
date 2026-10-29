using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class EligibilityRuleConfiguration : IEntityTypeConfiguration<EligibilityRule>
{
    public void Configure(EntityTypeBuilder<EligibilityRule> builder)
    {
        builder.ToTable("eligibility_rules");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(e => e.IsEnabled).IsRequired();
        builder.Property(e => e.CreatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(e => e.PublicId).IsUnique();
        builder.HasIndex(e => new { e.PrincipalId, e.EntitlementId }).IsUnique();

        builder.HasOne(e => e.Principal)
               .WithMany(e => e.EligibilityRules)
               .HasForeignKey(e => e.PrincipalId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(e => e.Entitlement)
               .WithMany(e => e.EligibilityRules)
               .HasForeignKey(e => e.EntitlementId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
