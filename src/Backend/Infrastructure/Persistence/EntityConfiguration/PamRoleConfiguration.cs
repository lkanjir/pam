using Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class PamRoleConfiguration : IEntityTypeConfiguration<PamRole>
{
    public void Configure(EntityTypeBuilder<PamRole> builder)
    {
        builder.ToTable("pam_roles");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).ValueGeneratedOnAdd();
        builder.Property(e => e.Code).IsRequired();
        builder.Property(e => e.Description).IsRequired();
        builder.Property(e => e.CreatedAt).HasDefaultValueSql("now()");

        builder.HasIndex(e => e.Code).IsUnique();

        builder.HasOne<Principal>()
               .WithMany()
               .HasForeignKey(e => e.CreatedByPrincipalId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
