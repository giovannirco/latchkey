---
# SPDX-License-Identifier: GPL-3.0-or-later
name: Latchkey Pages Installer
description: A quiet workspace for commissioning a local lock controller over USB.
colors:
  teal: "#126a65"
  teal-dark: "#0d514d"
  ink: "#20343b"
  muted: "#52676c"
  paper: "#edf5f5"
  line: "#c8dadb"
  white: "#fff"
  warning: "#8b381f"
  warning-bg: "#fff2eb"
typography:
  display:
    fontFamily: "'Avenir Next', Avenir, 'Segoe UI', sans-serif"
    fontSize: "clamp(2.7rem, 4.2vw, 3.7rem)"
    fontWeight: 650
    lineHeight: 1.06
    letterSpacing: "-.04em"
  headline:
    fontFamily: "'Avenir Next', Avenir, 'Segoe UI', sans-serif"
    fontSize: "1.85rem"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-.025em"
  body:
    fontFamily: "'Avenir Next', Avenir, 'Segoe UI', sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.55
  small:
    fontFamily: "'Avenir Next', Avenir, 'Segoe UI', sans-serif"
    fontSize: ".85rem"
rounded:
  field: "5px"
  control: "7px"
  workspace: "16px"
spacing:
  compact: ".5rem"
  inline: ".75rem"
  standard: "1rem"
  section: "1.5rem"
  panel: "2rem"
components:
  button-primary:
    backgroundColor: "{colors.teal}"
    textColor: "{colors.white}"
    rounded: "{rounded.control}"
    padding: ".7rem 1.25rem"
  button-primary-hover:
    backgroundColor: "{colors.teal-dark}"
    textColor: "{colors.white}"
  button-secondary:
    backgroundColor: "{colors.white}"
    textColor: "{colors.teal}"
    rounded: "{rounded.control}"
    padding: ".7rem 1.25rem"
  button-text:
    backgroundColor: "transparent"
    textColor: "{colors.teal}"
    padding: ".45rem 0"
  input:
    backgroundColor: "{colors.white}"
    textColor: "{colors.ink}"
    rounded: "{rounded.field}"
    padding: ".65rem .75rem"
  navigation:
    textColor: "{colors.teal}"
  progress:
    textColor: "{colors.muted}"
  board-option:
    rounded: "{rounded.control}"
    padding: "1rem"
  workspace:
    backgroundColor: "{colors.white}"
    rounded: "{rounded.workspace}"
  notice:
    backgroundColor: "{colors.paper}"
    textColor: "{colors.ink}"
    padding: ".9rem 1rem"
---

# Design System: Latchkey Pages Installer

## Overview

**Creative North Star: "The Commissioning Workspace"**

This document records the implemented GitHub Pages installer in `docs/index.html` and `docs/installer.css`. It does not define the firmware interface in `web/`. The design was derived from the implementation; the descriptive language here is documentation, not a record of explicit user style approval.

Purpose and progress occupy the left column. One active task occupies the white workspace on the right, beneath persistent USB connection status. Clear labels, restrained teal, and flat surfaces keep attention on the next action. There is no ambient motion or decorative imagery.

**Key Characteristics:**

- Four real setup steps, with supporting panels inside the current step.
- Teal actions and white surfaces against a pale ice background.
- Local system typography and visible keyboard focus.
- Release metadata inside the installation task.

## Colors

Teal provides the primary accent; cool neutrals separate content without visual weight.

- **Deep teal:** primary actions, links, current progress, selection and focus. Dark teal identifies hover.
- **Ink and muted slate:** primary text and supporting instructions respectively.
- **Ice paper, white and pale line:** page background, workspace and quiet separators.
- **Rust warning and warm warning paper:** destructive consequences and errors, always accompanied by text.

**The State Rule.** Use text and native control state alongside color to communicate selection, connection and errors.

## Typography

The local Avenir Next / Avenir / Segoe UI stack serves both headings and body text. No font download is required. Display and task headings use the frontmatter hierarchy; section titles use a compact bold treatment (1.05rem). Body paragraphs stop at 70ch.

On narrow screens the display heading uses 2.7rem and task headings use 1.6rem. Labels remain sentence case. Technical fingerprints wrap within their available width.

**The Heading Rule.** Keep the display heading's measured tracking; avoid tightening it further or adding an eyebrow above it.

## Layout

The shared container caps at 1160px with 5rem total horizontal inset. The desktop setup grid uses `minmax(260px, .8fr) minmax(0, 1.5fr)`, a fluid gap (`clamp(2rem, 6vw, 5.5rem)`), and 3.5rem top / 4rem bottom spacing. Panels use the panel spacing token.

At 850px and below, total inset becomes 3rem, the left column minimum becomes 220px, the gap becomes 2rem, panel padding becomes 1.5rem, and form fields stack. At 680px and below, total inset becomes 2rem, setup becomes one column, the four progress markers form a row, and panel padding becomes 1.4rem vertically / 1.2rem horizontally. Secondary intro copy and progress subtitles are hidden at that breakpoint.

The four steps are Install & connect, Make it yours, Bring your keys, and Open Latchkey. Authenticator saving and owner recovery are supporting panels, not extra progress steps. Downloads and technical disclosures follow the workspace.

**The Task Rule.** Keep USB status above the active task and release metadata within installation.

## Elevation & Depth

The workspace has no shadow. White against ice paper, thin borders and spacing establish grouping. The selected board alone uses an inset selection stroke (`inset 0 0 0 1px var(--teal)`). It indicates state, not elevation. Hover changes color immediately; there are no transitions or animations in the installer stylesheet.

## Shapes

The workspace, controls and fields use the three radius tokens. Progress numbers are circular (33px). Dividers, notice left borders and backup scope left borders are 1px. The USB status dot is 7px. Reserve filled surfaces for the workspace, controls, selection and messages.

## Components

- **Buttons:** primary teal, secondary white with a pale border, or underlined text. Standard buttons have a 48px minimum height; text buttons use 44px, with the compact disconnect control at 30px. Disabled primary buttons use `#e3ebec` with muted text and a not-allowed cursor.
- **Fields:** white with a `#a9c1c4` border and 46px minimum height; readonly fields use ice paper. Labels remain visible above fields. Radio and checkbox controls use native semantics and an 18px size.
- **Board choices:** full-row radio labels. Selection adds a pale tint (`#f3f9f8`), teal border and inset stroke. The trailing chip name is plain text, not a pill badge; it hides at the middle breakpoint.
- **Progress:** numbered markers and thin connecting lines. Current step uses a teal fill and `aria-current`; completed steps use a teal outline.
- **Workspace:** a single bordered container with persistent connection text, an optional disconnect action, and task-local notices. The connection row has a 54px minimum height.
- **Notices:** flat tinted blocks with a thin left border. Errors use `role="alert"`; connection and result text use `role="status"`.
- **Navigation:** compact text links, with Downloads and GitHub in the header. Supporting details use native disclosure controls.

**The Focus Rule.** Preserve the teal keyboard outline (3px with 4px offset), the skip link and focusable task headings.

## Do's and Don'ts

### Do:

- Do keep one active task inside the persistent USB workspace.
- Do place destructive consequences beside the action and its acknowledgement.
- Do preserve native controls, visible labels and keyboard focus.
- Do keep release details inside installation and technical downloads below setup.

### Don't:

- Don't apply this installer specification to the firmware interface without a separate design decision.
- Don't add ambient motion, decorative imagery or a workspace shadow.
- Don't replace the four real steps with decorative progress.
- Don't hide errors or use color alone to communicate state.
