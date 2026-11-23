using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddResourceApprovalAuthorityKind : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_resource_principal_bindings_kind",
                table: "resource_principal_bindings");

            migrationBuilder.AddCheckConstraint(
                name: "ck_resource_principal_bindings_kind",
                table: "resource_principal_bindings",
                sql: "kind IN ('ViewResource', 'ApproveRequests')");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_resource_principal_bindings_kind",
                table: "resource_principal_bindings");

            migrationBuilder.AddCheckConstraint(
                name: "ck_resource_principal_bindings_kind",
                table: "resource_principal_bindings",
                sql: "kind IN ('ViewResource')");
        }
    }
}
