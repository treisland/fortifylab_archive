# Changelog

All notable changes will be documented in this file.

The project uses [Semantic Versioning](https://semver.org/) for Fortify Lab
Manager releases. Manager versions are independent of Fortify component
platform profiles.

## [Unreleased]

### Added

- Repository governance and contribution guidance.
- Baseline repository validation and lifecycle regression checks.
- Foundational Fortify Lab Manager architecture decisions and their index.
- Private Telegram and GitHub SDLC supervisor with durable approvals,
  merge-state monitoring, and automatic next-issue queueing.

### Fixed

- ScanCentral SAST lifecycle operations now use the chart's actual sensor
  StatefulSet consistently.
- ScanCentral DAST Core stop now scales down each StatefulSet created by the
  chart.
