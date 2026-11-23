# Authorization baseline verification

Branch: `codex/fine-grained-authorization`, based on `feature/resource-crud`
at `10f567c`. Review each adjacent implementation/test commit pair together.
This baseline protects the delivered API and adds principal/role/scope management;
approval decisions, grants and provisioning remain Sprint 2 features.

## Automated gate

Final `bash scripts/check.sh` passed on **2026-11-21** at code/test checkpoint
`c9393e5`: **227 unit + 1,021 integration tests**, **0 failed, 0 skipped**.
The Release build had **0 warnings and 0 errors**. Pinned skill integrity (15
skills / 69 files), locked restore, formatting and analyzer checks all passed.
Integration tests used isolated PostgreSQL 18 and Redis containers.
Focused bootstrap, handover, pagination-index, publication and orphan-cleanup
suites passed before the full gate. No live database migration is performed.

## Requirement evidence

These are exact test method names; parameterized cases cover the sibling states
and boundaries described by each test. The table identifies representative
contract evidence, rather than substituting test volume for coverage.

| Requirement | Evidence |
| --- | --- |
| Explicit permission bundles without inheritance | `Authorize_ResourceManagementRead_UsesOnlyExplicitAuthenticatedAdmin`, `Authorize_ScopedRead_UsesExplicitOverlappingBundles`, `Authorize_OwnerRead_RequiresExplicitUserCapability` |
| Independent requester view and eligibility | `ListRequestable_ViewWithoutEligibilityAndEligibilityWithoutView_AreIndependent`, `AssignEligibility_WithoutView_DoesNotRevealResourceOrGrantRoles` |
| Scope filtering before pagination and retained owner history | `ListRequestable_HiddenRowsBetweenVisibleRows_AreFilteredBeforeCursorPagination`, `Submit_VisibilityRemovedAfterCreation_ReplaysOriginalAndPreservesOwnerHistory` |
| Resource-level approval authority without requester or self-authority bypass | `AssignAuthority_CombinedUserApprover_StillNeedsIndependentRequesterView`, `RevokeAuthority_OwnScope_ForbiddenBeforeDesiredStateNoOp` |
| Current role/status enforcement and bounded session restoration | `Write_DirectServiceCaller_CannotBypassCurrentIdentityCapabilityOrFreshness`, `Enable_PreviouslyDisabledAccount_RejectsUnusedOldCookieAndAcceptsNewLogin`, `Remove_ThenRegrant_DoesNotReviveUnusedCookieOrEligibility` |
| Last permanent Admin under concurrent changes | `Disable_TwoAdminsCrossDisabling_OnlyFirstCommitsAndOneAdminRemains`, `Remove_TwoAdminsCrossRemoving_OnlyFirstCommitsAndOneAdminRemains` |
| Original recent authentication and validated OIDC protocol | `Write_RequiresOriginalRecentAuthentication`, `Callback_FreshSameIdentity_ReplacesOnlyOriginalSession`, `Callback_InvalidFreshnessIdentityOrProtocol_LeavesOriginalSessionActive` |
| Complete endpoint classification including bootstrap boundary | `Start_EndpointWithoutCompleteAuthorization_RejectsBeforeServing`, `Start_BusinessPolicyWithoutBootstrapBoundary_RejectsBeforeServing` |
| Audited conditional assignment mutations and role-loss deactivation | `AssignEligibility_RequiredAuditRejected_RollsBackNewOrRetainedRuleAndParentVersion`, `Remove_RequiredAuthorityDeactivationAuditFails_RollsBackRoleAndScope` |
| Retained authorization review with consistent ETag | `Get_RetainedAuthorization_ReturnsExactConfiguredCountsAndUsableCollectionLinks`, `Get_GlobalSplitQuery_StillUsesOneReadOnlyStatementForStateAndVersion` |
| Controlled one-time installation with atomic audit | `Initialize_VerifiedOpaqueIdentity_CreatesRestrictedAdminAndAtomicInstallationAudit`, `Initialize_AuditRejected_RollsBackIdentityRoleAndInstallation`, `Initialize_RepeatedOrConcurrentInstaller_OnlyOneIdentityAndAuditSurvive` |
| Restricted temporary identity at HTTP and service boundaries | `Authorize_BootstrapWithEveryBundle_OnlyAllowsInstallationOperations`, `Bootstrap_DirectScopedRead_RemainsHiddenDespiteEveryBundleAndAssignment`, `Bootstrap_DirectSubmission_RemainsForbiddenDespiteEveryBundleAndAssignment` |
| Permanent authenticated handover, retirement and terminal replay | `Complete_PermanentFreshAdmin_RetiresAllBootstrapPermissionsWithExactAtomicAudits`, `Complete_AnyRequiredAuditRejected_RollsBackEntireHandover`, `Complete_CurrentCompletedRetry_IsNoOpAndCannotReactivateBootstrap`, `Complete_ConcurrentHandoverWithSameVersion_OnlyOneCommits` |
| Handover HTTP, service and OpenAPI contracts | `Complete_AuthenticationFreshnessCsrfVersionAndValidation_AreRequired`, `Complete_DirectCaller_RechecksCurrentIdentityFreshnessAndValidation`, `Complete_OpenApi_DocumentsMethodVersionAndSecurityFailures` |
| Ordered requester pagination index | `OwnRequestPaging_MigratedIndex_SupportsOwnerAndDescendingCursorWithoutSort` |
| Session publication expiry after acquiring the DB guard | `RecordStarted_ExpiryBoundary_PublishesOnlyBeforeDeadline`, `RecordStarted_DeadlinePassesWhileWaitingForPublicationLock_RechecksAfterLock` |
| Orphan cleanup without destroying published or renewed recovery records | `Run_UnpublishedMissingTicket_DiscardsLeaseOnlyAtOrAfterExpiryWithoutInventingAudit`, `Run_PublishedExpiredSession_PreservesKnownDeadlineForExactEndAudit`, `DiscardExpiredLease_RenewalChangesObservedLease_DoesNotDeleteCurrentRecoveryState` |
| Both publication/cleanup orderings and bounded native scan progress | `Run_CleanupCommitsBeforeDelayedPublication_ExpiredStartCannotAppearLater`, `Run_PublicationHasUncommittedLedger_WaitsBeforeClassifyingLeaseAsOrphan`, `ReadLeasePage_MultipleBoundedPasses_ResumesAcrossPageOffsetsWithoutStarvation` |

## Code quality review

The review traced API operation metadata into native ASP.NET authorization,
current SQL predicates and transactional writes. DTOs remain separate from EF
entities; configuration uses existing DI/options mechanisms. No dependency or
architecture change, custom permission expression language or generic repository
was needed. New endpoints document contracts through Minimal API metadata and
generated OpenAPI, with no `.http` request files.

Principal/status/role writes share the administration guard and ordered principal
locks. Resource-scoped writes lock the principal before the resource; request
submission follows the same order. ETags refer to the changed aggregate. Native
EF projections keep permission filters and cursor limits in SQL. Administrative
retained reads/updates explicitly bypass resource retirement filters. Per-row
bulk deactivation and audit are shared without materializing unbounded collections.

Sensitive commands repeat current identity, role and original-authentication-time
checks inside their transaction. Audit rejection rolls back all related changes.
Bootstrap restrictions apply independently of any extra assigned bundles and
normal APIs cannot reactivate its retained identity. Redis availability cannot
undo committed DB retirement. Session cleanup and publication share a PostgreSQL
transaction advisory lock and use conditional Redis operations for observed state.

The bounded assertion/gap review covered authorization suites plus session
publication and orphan cleanup. Tests assert denial/absence of disclosure,
unchanged state on failure, exact audit actor/reason/time, version/no-op behavior,
retained relationships and both race orderings. Deterministic clocks and explicit
database/transaction gates replace timing sleeps. The review added direct bootstrap
service and generated OpenAPI cases where HTTP-only tests would mask service guards.
No executed mutation score is claimed. Static counterfactual review found the core
permission, self-change, audit rollback, expiry and cursor outcomes protected.

No further architecture refactor was identified as a prerequisite for the next
backend slice. Future groups/custom bundles can extend assignment subjects and
bundle composition while retaining the current capability names and invariants.

One existing scale follow-up remains outside the authz baseline:
`GET /api/resources?requestable=true` bounds resource pages but embeds every
eligible entitlement for each selected resource. Before introducing large
entitlement catalogs, add a paginated requester-entitlement contract and migrate
that inline collection explicitly. The management entitlement endpoint is already
bounded; it does not change this requester contract. Silently truncating the
existing collection would change what clients can select and is not a safe fix.

## Remaining release work

- Run a live Keycloak/browser smoke for account switching, original authentication
  freshness and the operator handover. Automated OIDC tests use the real framework
  callback with a local signed identity-provider double; they do not prove live
  Keycloak configuration or a human login.
- Review the generated schema SQL, apply it manually through the production DB
  administrator, and follow the [controlled installation runbook](bootstrap-installation.md)
  only for a new installation. Exporting SQL does not apply it.
  The local review export is `artifacts/db-authz-review-20261121/schema.sql`, from
  `20261115002722_AddOpenSessionReconciliationIndex` through
  `20261121191444_AddRequesterRequestPagingIndex`. It contains seven schema
  migrations, replaces the two generic indexes with the targeted disabled-account
  audit/open-session indexes, and adds typed bindings, installation state and the
  requester paging index. It contains no account provisioning or credentials.
- Review/merge the baseline before starting scoped approval reads and the complete
  decision/grant/provisioning transaction. Groups, custom roles and actual approval
  decisions are intentionally outside this delivery.

## Planned onboarding follow-up

Track **BOOTSTRAP-UX-01** in Sprint 2 planning or the frontend-onboarding milestone:
automatically provision the temporary Keycloak/PAM bootstrap identity, guide setup
and verified permanent-Admin handover, then automate Keycloak retirement. The
[first-start plan](bootstrap-installation.md#planned-first-start-experience) records
the remaining installer/frontend work and acceptance criteria. This future flow
replaces manual account-bootstrap SQL; it does not change production schema
migration policy. Existing automated baseline results above do not claim this
onboarding automation is implemented or tested.
