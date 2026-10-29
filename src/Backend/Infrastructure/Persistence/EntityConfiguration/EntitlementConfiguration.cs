using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class EntitlementConfiguration : IEntityTypeConfiguration<Entitlement>
{
    public void Configure(EntityTypeBuilder<Entitlement> builder)
    {
        builder.ToTable("entitlements");
        builder.ToTable(t => t.HasCheckConstraint("ck_entitlements_max_duration_minutes", "max_duration_minutes > 0"));
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(e => e.Code).IsRequired();
        builder.Property(e => e.Name).IsRequired();
        builder.Property(e => e.MaxDurationMinutes).IsRequired();
        builder.Property(e => e.IsActive).IsRequired();

        builder.HasIndex(e => e.PublicId).IsUnique();
        builder.HasIndex(e => new { e.ResourceId, e.Code }).IsUnique();

        // Historical queries that traverse Resource must explicitly use IgnoreQueryFilters().
        builder.HasOne(e => e.Resource)
               .WithMany(e => e.Entitlements)
               .HasForeignKey(e => e.ResourceId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
