using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class PamInstallationConfiguration : IEntityTypeConfiguration<PamInstallation>
{
    public void Configure(EntityTypeBuilder<PamInstallation> builder)
    {
        builder.ToTable("pam_installation", table =>
        {
            table.HasCheckConstraint("ck_pam_installation_singleton", "id = 1");
            table.HasCheckConstraint("ck_pam_installation_completion", "(completed_at IS NULL) = (completed_by_principal_id IS NULL)");
            table.HasCheckConstraint("ck_pam_installation_time", "completed_at IS NULL OR completed_at >= initialized_at");
        });
        builder.HasKey(installation => installation.Id);
        builder.Property(installation => installation.Id).ValueGeneratedNever();
        builder.Property(installation => installation.Version).IsRowVersion().HasColumnName("xmin");
        builder.HasIndex(installation => installation.BootstrapPrincipalId).IsUnique();
        builder.HasOne(installation => installation.BootstrapPrincipal).WithMany()
            .HasForeignKey(installation => installation.BootstrapPrincipalId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne(installation => installation.CompletedByPrincipal).WithMany()
            .HasForeignKey(installation => installation.CompletedByPrincipalId).OnDelete(DeleteBehavior.Restrict);
    }
}
