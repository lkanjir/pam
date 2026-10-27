using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class PamRoleAssignmentConfiguration : IEntityTypeConfiguration<PamRoleAssignment>
{
    public void Configure(EntityTypeBuilder<PamRoleAssignment> builder)
    {
        builder.ToTable("pam_role_assignments");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.Id).UseIdentityByDefaultColumn();
        builder.Property(e => e.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(e => e.AssignedAt).HasDefaultValueSql("now()");

        builder.HasIndex(e => e.PublicId).IsUnique();
        builder.HasIndex(e => new { e.PrincipalId, e.RoleId }).IsUnique();

        builder.HasOne<Principal>()
               .WithMany()
               .HasForeignKey(e => e.PrincipalId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<PamRole>()
               .WithMany()
               .HasForeignKey(e => e.RoleId)
               .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<Principal>()
               .WithMany()
               .HasForeignKey(e => e.AssignedByPrincipalId)
               .OnDelete(DeleteBehavior.Restrict);
    }
}
