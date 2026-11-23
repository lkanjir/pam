using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddDisabledAccountAuditLookupIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_audit_events_subject_principal_id",
                table: "audit_events");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_last_account_disable",
                table: "audit_events",
                columns: new[] { "subject_principal_id", "id" },
                filter: "event_type = 'principal.disabled'");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_audit_events_last_account_disable",
                table: "audit_events");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_subject_principal_id",
                table: "audit_events",
                column: "subject_principal_id");
        }
    }
}
