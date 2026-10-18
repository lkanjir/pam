using Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class PrincipalConfiguration : IEntityTypeConfiguration<Principal>
{
    public void Configure(EntityTypeBuilder<Principal> builder)
    {
        builder.ToTable("principals");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(e => e.Issuer).IsRequired();
        builder.Property(e => e.Subject).IsRequired();
        builder.Property(e => e.DisplayName).IsRequired();
        builder.Property(e => e.IsEnabled).IsRequired();
        builder.Property(e => e.CreatedAt).HasDefaultValueSql("now()");
        builder.Property(e => e.ModifiedAt).HasDefaultValueSql("now()");

        builder.HasIndex(e => e.PublicId).IsUnique();
        builder.HasIndex(e => new { e.Issuer, e.Subject }).IsUnique();
    }
}
