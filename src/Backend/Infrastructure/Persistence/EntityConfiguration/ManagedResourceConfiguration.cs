using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class ManagedResourceConfiguration : IEntityTypeConfiguration<ManagedResource>
{
    public void Configure(EntityTypeBuilder<ManagedResource> builder)
    {
        builder.ToTable("managed_resources");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(e => e.Name).IsRequired();
        builder.Property(e => e.ResourceType).IsRequired();
        builder.Property(e => e.Environment).IsRequired();
        builder.Property(e => e.IsActive).HasDefaultValue(true);
        builder.Property(e => e.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(e => e.ModifiedAt).HasDefaultValueSql("now()");

        builder.HasQueryFilter(e => e.DeletedAt == null);

        builder.HasIndex(e => e.PublicId).IsUnique();

        builder.HasOne(e => e.CreatedByPrincipal)
            .WithMany()
            .HasForeignKey(e => e.CreatedByPrincipalId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne(e => e.ModifiedByPrincipal)
            .WithMany()
            .HasForeignKey(e => e.ModifiedByPrincipalId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
