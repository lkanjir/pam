using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.Persistence.EntityConfiguration;

public sealed class ResourcePrincipalBindingConfiguration : IEntityTypeConfiguration<ResourcePrincipalBinding>
{
    public void Configure(EntityTypeBuilder<ResourcePrincipalBinding> builder)
    {
        builder.ToTable("resource_principal_bindings", table => table.HasCheckConstraint(
            "ck_resource_principal_bindings_kind", "kind IN ('ViewResource', 'ApproveRequests')"));
        builder.HasKey(binding => binding.Id);
        builder.Property(binding => binding.Id).UseIdentityByDefaultColumn();
        builder.Property(binding => binding.PublicId).HasDefaultValueSql("uuidv7()");
        builder.Property(binding => binding.Kind).HasConversion<string>().HasMaxLength(32);
        builder.Property(binding => binding.IsActive).HasDefaultValue(true);
        builder.Property(binding => binding.Version).IsRowVersion().HasColumnName("xmin");
        builder.HasIndex(binding => binding.PublicId).IsUnique();
        builder.HasIndex(binding => new { binding.PrincipalId, binding.Kind, binding.ResourceId }).IsUnique();
        builder.HasIndex(binding => new { binding.ResourceId, binding.Kind, binding.PrincipalId });
        builder.HasOne(binding => binding.Principal).WithMany(principal => principal.ResourceBindings)
            .HasForeignKey(binding => binding.PrincipalId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne(binding => binding.Resource).WithMany(resource => resource.PrincipalBindings)
            .HasForeignKey(binding => binding.ResourceId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne(binding => binding.AssignedByPrincipal).WithMany()
            .HasForeignKey(binding => binding.AssignedByPrincipalId).OnDelete(DeleteBehavior.Restrict);
        builder.HasOne(binding => binding.ModifiedByPrincipal).WithMany()
            .HasForeignKey(binding => binding.ModifiedByPrincipalId).OnDelete(DeleteBehavior.Restrict);
        builder.HasQueryFilter(binding => binding.Resource != null && binding.Resource.DeletedAt == null);
    }
}
