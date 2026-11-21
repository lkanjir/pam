using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPrincipalOpenSessionCleanupIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_authentication_session_ledger_principal_id",
                table: "authentication_session_ledger");

            migrationBuilder.CreateIndex(
                name: "ix_authentication_session_ledger_open_principal_id",
                table: "authentication_session_ledger",
                columns: new[] { "principal_id", "id" },
                filter: "ended_at IS NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_authentication_session_ledger_open_principal_id",
                table: "authentication_session_ledger");

            migrationBuilder.CreateIndex(
                name: "ix_authentication_session_ledger_principal_id",
                table: "authentication_session_ledger",
                column: "principal_id");
        }
    }
}
