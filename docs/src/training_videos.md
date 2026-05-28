# Patina Training Videos

The Patina project occassionally produces training videos to supplement the documentation. These videos are intended
to provide a more visual and interactive way to learn about the project, its architecture, and how to contribute. It
is recommended to watch these videos in order and to review the associated documentation for a more comprehensive
understanding of the project.

Videos are uploaded to the [Patina Training YouTube playlist](https://www.youtube.com/playlist?list=PLYfE1InHU3kY_6EbppM2SDIQBSr5ReIVe)
in the [Open Device Partnership YouTube channel](https://www.youtube.com/@OpenDevicePartnership).

---

## Project Introduction

An overview of Patina, featuring an introduction, a high-level architectural breakdown, primary Patina use cases, and
a brief tour of the GitHub repository.

<!-- cSpell:disable -->
- Presenter: [Michael Kubacki](https://github.com/makubacki)
<!-- cSpell:enable -->

<div style="text-align: center; margin: 20px 0;">
  <iframe width="853" height="480"
    src="https://www.youtube.com/embed/khxktipnSDE"
    title="YouTube: May 2026 Patina Training - Project Introduction"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen>
  </iframe>
</div>

## Creating a Platform DXE Core and Integrating Components

Covers the creation and integration of a platform-specific customized DXE Core, including how to incorporate Patina
components into the platform’s DXE Core.

<!-- cSpell:disable -->
- Presenter: [Joey Vagedes](https://github.com/javagedes)
<!-- cSpell:enable -->

<div style="text-align: center; margin: 20px 0;">
  <iframe width="853" height="480"
    src="https://www.youtube.com/embed/KKPqYayPGko"
    title="YouTube: May 2026 Patina Training - Creating a Platform DXE Core and Integrating Components"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen>
  </iframe>
</div>

## Patina QEMU Developer Workflow

Demonstrates how to build Patina Rust firmware, integrate it into a QEMU firmware image, and boot to the UEFI shell.
This is the core developer workflow for implementing and testing project changes.

<!-- cSpell:disable -->
- Presenter: [Joey Vagedes](https://github.com/javagedes)
<!-- cSpell:enable -->

<div style="text-align: center; margin: 20px 0;">
  <iframe width="853" height="480"
    src="https://www.youtube.com/embed/PwXNWhc5Rq8"
    title="YouTube: May 2026 Patina Training - Patina QEMU Developer Workflow"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen>
  </iframe>
</div>

Commands demonstrated in the video:

- 1:50 - `py -m venv venv_wizard`
- 2:05 - `.\venv_wizard\scripts\activate`
- 2:20 - `py .\workspace_setup.py`
- 4:25 - `py .\workspace_setup.py`
- 4:50 - `..\patina-fw-patcher`
- 5:05 - `..\patina-dxe-core-qemu`
- 5:15 - `..\patina`
- 6:35 - `py .\workspace_setup.py`
- 7:50 - `py .\workspace_setup.py`
- 9:00 - `py .\workspace_setup.py`

## Source Debugging

Learn how to source-level debug Patina, including an overview of the supporting components and available tools, with a
hands-on demonstration in WinDbg. Applicable to both physical and virtual platforms.

<!-- cSpell:disable -->
- Presenter: [Chris Fernald](https://github.com/cfernald)
<!-- cSpell:enable -->

<div style="text-align: center; margin: 20px 0;">
  <iframe width="853" height="480"
    src="https://www.youtube.com/embed/duCRDRpJAT4"
    title="YouTube: May 2026 Patina Training - Source Debugging"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
    allowfullscreen>
  </iframe>
</div>
