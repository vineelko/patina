# RFC: Patina Code First Process

This RFC defines a code first process for the Patina project. A code first process allows source code to be developed
in tandem with specification and design documents. This allows for a more iterative development process where design
decisions can be validated through implementation and testing before being finalized in documentation.

The Patina Code First process intends to be very lightweight reducing overhead for managing source code changes. While
this iteration of the RFC focuses on specifications maintained by the UEFI Forum, the process defined here is expected
to be updated/extended in the future to cover other specifications on an as needed basis.

## Change Log

- 2026-04-30: Initial RFC created.

## Motivation

As a firmware project, Patina must frequently implement source code for changes actively being defined in specifications,
particularly for new firmware capabilities and interfaces and hardware technologies. The code first process allows
Patina to implement and test code in parallel with specification drafts. This has the dual benefits of building confidence
in specification design decisions while also resulting in earlier implementation readiness.

As a UEFI project, Patina will frequently employ the code first process in collaboration with the UEFI Forum. In this
case , the process lets changes and development of new features happen in open source, without violating the UEFI Forum
bylaws which otherwise prevent publication of code for in-draft features/changes as they are under UEFI NDA.

Finally, since Patina is a Rust project, code first implementation provides an opportunity to influence specification
design with insights from Rust language features and design patterns and even idiomatic Rust APIs. This is an important
step toward reducing the dependency on C language design patterns and APIs in UEFI specifications.

## Goals

Goal: Define a process that allows Patina source code to be developed alongside ECRs for UEFI Forum specifications.

## Unresolved Questions

- Outside the purview of Patina: But can the UEFI Forum maintain public specification source files (markdown/rst) in
  in a publicly accessible repository? That would make it much easier for developers writing draft changes for their
  code first change to copy, paste, and modify existing specification source files for their change.
  - Even more ideal would be if the UEFI Forum maintained a public repository for specification changes in the form of
    pull requests that could be linked to code first pull requests in Patina. This would allow for even better tracking
    of exactly which specification changes are related to which code changes and would make it easier for developers to
    keep specification changes up to date with code changes and vice versa.

## Prior Art

The most substantial prior art for this RFC is the [EDK II Code First Process](https://www.tianocore.org/tianocore-wiki.github.io/development/contribution-guides/edk_ii_code_first_process.html).
The most notable differences from that process is that Patina does not require source code annotation
(e.g. code comments).

## Alternatives

1. Implement code changes after specification changes are finalized and published.
   - Rejected because: This results in a longer development process and delays feedback on design decisions until after
     code is implemented.
2. Implement code changes in a private repository.
   - Rejected because: This prevents the benefits of open source development and collaboration.
3. Implement code changes in a public repository without any process for formally describing specification
   modifications.
   - Rejected because: This would make it difficult to track exactly what the change is attempting to implement. All
     community members might not have access to the ECR. In addition to which code changes are related to which
     specification changes increasing likelihood of confusion an lack of coordination between code and specification
     development.

## The Process

Order of operations are important in the code first process. It is essential to create the "tracking" issue and pull
request in the Patina repository before submitting an ECR or engaging with the specification body. If the ECR or
specification body engagement happens first, the process is no longer considered "code first" and potentially under
an NDA which would prevent code from being developed in an open source repository.

It is also important to carefully share details in working groups for the same reason. Details should generally be
limited to information necessary for basic review and Q&A to complete the approval process. All feedback must be
submitted to the PR/issue in Patina so it can be responded to/acted upon before going back to the working group for
specification inclusion.

The code first author:

1. Creates a new "tracking" issue in the Patina repository using the "Code First" GitHub issue form.
   - Ensure all specifications impacted by the change are selected in the form.
   - The issue must have the `type:code-first` label applied to it.
     - Note: This should happen automatically if the "Code First" form is used to create the issue.
   - This issue must remain open until the code first change being tracked is published in the relevant specification(s)
     and all code changes are merged into the default branch (`main`) of the `OpenDevicePartnership/patina` repository.
     - Note: This means that PRs to implement the code first change should not close this issue when merged.
2. Creates a local branch (for the code first change).
   - Note: This is referred to as the "code first branch" in later steps.
3. Writes a specification draft change in a markdown file included in a standalone commit on the "code first branch".
   The file must use the [Code First Template](../../code_first/template.md) and be placed in the `docs/src/code_first`
   directory of the Patina source tree.
   - The file should be named: `<GitHub issue number>-<short-description>.md` (e.g. `123-add-feature-x.md`).
   - Note: A file must be present for each specification if more than one specification is impacted by the change.
4. Authors the code first implementation in the "code first branch" using one or more commits as appropriate.
5. Pushes the "code first branch" to their fork (e.g. `username/patina`).
6. Creates a pull request into the default branch (`main`) of the `OpenDevicePartnership/patina` repository.
7. Applies the `type:code-first` label to the pull request.
8. Adds a link to the "tracking" issue created in Step 1 to the pull request description.
   - Example: "Code first tracking issue: \#123"
9. Adds specification working group members to the pull request. If they are members of the Patina organization on
   GitHub they must be added as reviewers. If they are not members of the Patina organization, they must be added as
   assignees or mentioned in the pull request description.
   - The pull request **cannot** be merged until the working group has approved the code changes.
10. Continues to develop the code change in the "code first branch" based on feedback.
11. Goes through the normal PR review process until the PR is approved and merged.

### GitHub Code First Issue Template Example

```markdown
name: </> Code First
description: Code first tracking issue
title: "[Code First]: <title>"
labels: ["type:code-first"]

body:
  - type: markdown
    attributes:
      value: |
        Introductory text for the GitHub issue

  - type: textarea
    id: overview
    attributes:
      label: Code First Item Overview
      description: Provide a brief overview of the overall code first change.
    validations:
      required: true

  - type: dropdown
    id: specs_impacted
    attributes:
      label: What specification(s) are directly related?
      description: |
        *Select all that apply*
      multiple: true
      options:
        - ACPI
        - Platform Initialization (PI)
        - UEFI
        - UEFI PI Distribution Packaging
        - UEFI Shell
    validations:
      required: true

  - type: textarea
    id: anything_else
    attributes:
      label: Anything else?
      description: |
        Links? References? Anything that will give us more context about the code first change.

        - Update this section to include links to any pull requests associated with the code first change as they are
          created.

        - Update this section to include links to the "code first" markdown file for this change after it is merged
          into the default branch (`main`) of the `OpenDevicePartnership/patina` repository.

        Tip: You can attach images or log files by clicking this area to highlight it and then dragging files in.
    validations:
      required: false
```
