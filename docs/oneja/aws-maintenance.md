# OneJA Code Interpreter maintenance

Application baseline: fork commit `cb56d4c6c31f77f96236a4e8758fdf449cbebc89`.
Preserve the existing document-tooling customisations and MCP continuation-file
handoff. ECS, IAM, networking, storage, image publication and release tooling
belong in `jaworldwideorg/oneja-ai-infrastructure`.

The only application exception retained from the AWS migration is in
`api/src/entrypoint.sh`: the trusted startup document-toolchain check has a
30-second NsJail time limit and a 45-second outer timeout. User-code execution
limits are unchanged. The operator explicitly accepted this exception on
1 November 2026 after the original check failed in both AWS snapshot attempts
at its six-second limit. ECS is not the reason for this fix; the existing
expanded document tooling needs more startup time in Lambda MicroVMs.

The removed migration overlay is not required for this release: no custom
DynamoDB VM admission, hosted-app preview changes, warm-session recovery
overlay, or Redis certificate/reconnect patches are retained. Native baseline
behaviour applies, including its original TLS/reconnect limitations. Do not
reintroduce these changes as part of an infrastructure update.

For an upstream update:

1. Merge upstream into an isolated candidate branch. Preserve the MCP
   continuation-file handoff and the pre-existing customisations.
2. Review whether upstream has addressed the startup verifier deadline. Remove
   this exception only after the original full tooling check passes in an AWS
   managed-image build; do not skip the check or relax user execution limits.
3. Install frozen service dependencies, run the ESM typecheck, service tests
   and `test:ptc`. The continuation-file and Lambda tests must pass.
4. Build immutable control and runner images and record their source commits
   separately in the infrastructure repository. Managed runner changes need
   an accepted immutable Lambda image version in addition to an ECR push.
5. Verify authentication, owner isolation, execution, uploaded/generated files
   and MCP replay handoff in staging before promoting production.

Current image digests, rollout status, credentials access and rollback steps
are recorded in the infrastructure repository's Code Interpreter guide and
release receipts. An image being published is not evidence of deployment.
