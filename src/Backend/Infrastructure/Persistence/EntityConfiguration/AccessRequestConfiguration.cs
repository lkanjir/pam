using Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class AccessRequestConfiguration : IEntityTypeConfiguration<AccessRequest>
{
    public void Configure(EntityTypeBuilder<AccessRequest> builder)
    {
        builder.ToTable("access_requests");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("gen_random_uuid()");
        builder.Property(e => e.State).IsRequired();
        builder.Property(e => e.IdempotencyKey).IsRequired();
        builder.Property(e => e.Justification).IsRequired();
        builder.Property(e => e.CreatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(e => e.PublicId).IsUnique();
        builder.HasIndex(e => new { e.RequesterPrincipalId, e.IdempotencyKey }).IsUnique();

        // CHECK: RequestedDurationMinutes > 0
        builder.ToTable(t => t.HasCheckConstraint("ck_access_requests_requested_duration_minutes", "requested_duration_minutes > 0"));

        builder.HasOne<Principal>()
               .WithMany()
               .HasForeignKey(e => e.RequesterPrincipalId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<Entitlement>()
               .WithMany()
               .HasForeignKey(e => e.EntitlementId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
