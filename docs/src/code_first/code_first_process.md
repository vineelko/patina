# Code First Process

The code first process allows Patina source code to be developed alongside draft specification changes
(e.g. UEFI Forum ECRs). Implementation and testing happen in parallel with specification drafting so that design
decisions are validated through working code before being finalized in a published specification.

This page is intended to provide a high-level overview of the code first process to supplement the formal definition in
[RFC 0027 - Code First](https://github.com/OpenDevicePartnership/patina/blob/main/docs/src/rfc/text/0027-code-first.md).
Once you have a good understanding of the process from this page, refer to the RFC for more details.

## When to Use Code First

Use this process when a Patina change depends on a specification modification that has **not yet** been brought to the
attention of the relevant specification working group. Common scenarios include:

- Implementing a new UEFI/PI protocol or interface.
- Modifying behavior governed by an existing specification clause that is being revised.
- Proposing a new specification feature where Patina serves as the reference implementation.

If the specification change is already published, the standard contribution workflow applies and code first is not
required.

## Key Principles

1. **Open source first** - The tracking issue and pull request in Patina must exist *before* any ECR submission to
   working-group engagement. This ordering keeps the work public and avoids NDA constraints.
2. **Specification draft included in-tree** - Every code first PR carries a markdown file in `docs/src/code_first/`
   (using the [Code First Template](template.md)) that captures the proposed specification text. One file per impacted
   specification. This ensures Patina developers can see key specification details even if they don't have access to the
   ECR or working group discussions.
3. **Working-group review on the PR** - Specification reviewers participate directly on the GitHub pull request. The PR
   cannot merge until working-group approval is obtained.
4. **Tracking issue stays open** - The code first tracking issue is closed only after the specification change is
   published *and* all related code is merged to `main`.

## Key Steps

| Step                | Location                                              | Purpose                                                       |
|---------------------|-------------------------------------------------------|---------------------------------------------------------------|
| Tracking issue      | GitHub Issues (`type:code-first` label)               | Tracks the lifecycle from draft through publication           |
| Specification draft | `docs/src/code_first/<issue_number>-<description>.md` | Proposed specification text using the [template](template.md) |
| Code first PR       | GitHub Pull Requests (`type:code-first` label)        | Contains the implementation and specification draft           |

## Other Resources

- [RFC 0027 - Code First](https://github.com/OpenDevicePartnership/patina/blob/main/docs/src/rfc/text/0027-code-first.md)
  \- Full process definition and rationale.
- [Code First Template](template.md) - Template for specification draft files.
