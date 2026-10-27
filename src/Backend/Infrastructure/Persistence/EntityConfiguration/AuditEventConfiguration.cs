using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> builder)
    {
        builder.ToTable("audit_events");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(e => e.EventType).IsRequired();
        builder.Property(e => e.ActorKind).IsRequired();
        builder.Property(e => e.CorrelationId).IsRequired();
        builder.Property(e => e.Source).IsRequired();
        builder.Property(e => e.SchemaVersion).HasDefaultValue(1);
        builder.Property(e => e.OccurredAt).HasDefaultValueSql("now()");
        builder.Property(e => e.ActorSnapshot).HasColumnType("jsonb");
        builder.Property(e => e.SubjectSnapshot).HasColumnType("jsonb");
        builder.Property(e => e.ResourceSnapshot).HasColumnType("jsonb");
        builder.Property(e => e.EntitlementSnapshot).HasColumnType("jsonb");
        builder.Property(e => e.Metadata).HasColumnType("jsonb");

        builder.HasIndex(e => e.PublicId).IsUnique();

        builder.HasOne<Principal>()
               .WithMany()
               .HasForeignKey(e => e.ActorPrincipalId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<Principal>()
               .WithMany()
               .HasForeignKey(e => e.SubjectPrincipalId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<ManagedResource>()
               .WithMany()
               .HasForeignKey(e => e.ResourceId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<Entitlement>()
               .WithMany()
               .HasForeignKey(e => e.EntitlementId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<AccessRequest>()
               .WithMany()
               .HasForeignKey(e => e.RequestId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
