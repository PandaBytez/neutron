---
name: neutron-docs-builder
description: Maintain and build Neutron's mdBook documentation and GitHub Pages workflows. Use when updating technical wiki docs in docs/, modifying book.toml, or configuring GitHub Pages deployment in .github/workflows/pages.yml.
---

# Neutron Documentation and mdBook Guide

Neutron's technical wiki is built with [mdBook](https://rust-lang.github.io/mdBook/) and automatically deployed to GitHub Pages via GitHub Actions.

## Configuration Standards (`book.toml`)

- **Default Theme:** The book uses `ayu` as its default and preferred dark theme:
  ```toml
  [output.html]
  default-theme = "ayu"
  preferred-dark-theme = "ayu"
  ```
- **Schema Compatibility:** Do NOT add deprecated keys such as `multilingual = false` under `[book]`. Recent mdBook versions strictly reject unknown fields.
- **Output Directory:** The build output is configured as `public/` (matching `.github/workflows/pages.yml` and ignored in `.gitignore`).

## Building and Serving Documentation

You can build and preview documentation locally using standard commands or Cargo aliases:

```sh
# Build static HTML documentation into public/
cargo docs

# Serve documentation locally on an ephemeral port with live reload
cargo xtask docs --serve

# Direct mdBook binary usage (if mdbook is installed)
mdbook build
mdbook serve
```

## GitHub Pages Deployment

- GitHub Pages is deployed via `.github/workflows/pages.yml` on pushes to `main`.
- The repository setting on GitHub must have **Pages -> Build and deployment -> Source** set to **GitHub Actions**.
- Artifacts are generated from the `public/` folder using `actions/upload-pages-artifact` and deployed with `actions/deploy-pages`.
