using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddPamInstallation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "pam_installation",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false),
                    bootstrap_principal_id = table.Column<long>(type: "bigint", nullable: false),
                    initialized_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    completed_at = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    completed_by_principal_id = table.Column<long>(type: "bigint", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_pam_installation", x => x.id);
                    table.CheckConstraint("ck_pam_installation_completion", "(completed_at IS NULL) = (completed_by_principal_id IS NULL)");
                    table.CheckConstraint("ck_pam_installation_singleton", "id = 1");
                    table.CheckConstraint("ck_pam_installation_time", "completed_at IS NULL OR completed_at >= initialized_at");
                    table.ForeignKey(
                        name: "fk_pam_installation_principals_bootstrap_principal_id",
                        column: x => x.bootstrap_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_pam_installation_principals_completed_by_principal_id",
                        column: x => x.completed_by_principal_id,
                        principalTable: "principals",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_pam_installation_bootstrap_principal_id",
                table: "pam_installation",
                column: "bootstrap_principal_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_pam_installation_completed_by_principal_id",
                table: "pam_installation",
                column: "completed_by_principal_id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "pam_installation");
        }
    }
}
