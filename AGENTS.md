# AGENTS.md

This document is the README for AI coding agents. It complements the human-facing README.md so that agents can develop safely and efficiently.

---

## 1. Setup Steps

* Recommended: VS Code Dev Container / GitHub Codespaces (use the `.devcontainer/` image).
* Base packages: `sudo apt-get install build-essential`.
* Rust toolchain: `rustup default stable` (rustfmt/clippy components are required).
* Helper tools: `make` (see the Makefile targets below).

---

## 2. Build & Validate

* Build: `make build`
* Test: `make test`
* Lint: `make lint`
* Cleanup: `make clean` or `cargo clean`.
* For CLI usage and command examples, see the Usage section in README.md.

---

## 3. Project Structure

We follow the **package layout described in The Cargo Book** for a project consisting of a single binary plus shared library code.

```
.
├── Cargo.toml
├── Cargo.lock
├── Makefile
├── src/
│   ├── lib.rs
│   ├── main.rs
│   └── bin/
│       ├── named-executable.rs
│       ├── another-executable.rs
│       └── multi-file-executable/
│           ├── main.rs
│           └── some_module.rs
└── tests/
    ├── some-integration-tests.rs
    └── multi-file-test/
        ├── main.rs
        └── test_module.rs
```

### Roles and Guidelines

* Keep business logic in `lib.rs` or `src/<module>.rs`; limit `main.rs` to startup/DI/argument handling.
* Integration tests go under `tests/`, exercising public APIs.
* Place new files under the directories above; avoid introducing new top-level folders without discussion.

### Agent-Specific Rules

* Place new files according to the directory guidelines above; avoid introducing unnecessary top-level directories.
* When modifying existing functions, add or update unit tests and confirm `make test` passes.
* When writing files or accessing external resources, use temporary directories so existing test data is not overwritten.


---

## 4. Coding Standards

* Always run `make fmt-check` so the code remains formatted.
* Run `make lint` for static checks and ensure there are no warnings (CI requirement).
* Prefer `thiserror` for error types; use `anyhow` only in binaries.
* Naming: modules in `snake_case`, types in `UpperCamelCase`.
* Extract magic numbers/URLs into constants with meaningful names.
* Avoid unrelated large refactors; keep changes minimal in scope.

---

## 5. Testing & Verification

* Unit tests: `make test`
* For additional file or network operations, use temp directories or `httptest` to avoid external dependencies.
* When command behavior changes, keep usage examples in `README.md` and fixtures under `test` consistent.

### Static Analysis / Lint / Vulnerability Scanning

* Static analysis: `make clippy`
* Code quality: `make fmt-check`
* Vulnerability scanning: `make audit`

---

## 6. CI Requirements

GitHub Actions (`.github/workflows/ci.yml`) runs the following:

* `make lint`
* `make test`
* `make build`

Confirm `make lint` / `make test` / `make build` succeed locally before opening a PR. If they fail, format and validate locally, then rerun.

---

## 7. Security & Data Handling

* Do not commit secrets or confidential information.
* Do not log personal or authentication data in logs or error messages.
* Use fictitious URLs and passwords in test data; avoid hitting real services.
* Obtain user approval before accessing external networks (disabled by default in the agent environment).

---

## 8. Agent Notes

* If multiple `AGENTS.md` files exist, reference the one closest to your working directory (this repository only has the top-level file).
* When instructions conflict, prioritize explicit user prompts and clarify any uncertainties.
* Before and after your work, ensure `make lint`, `make test`, and `make build` all succeed; report the cause and fix if any of them fail.


---

## 9. Branch Workflow (GitHub Flow)

This project follows **GitHub Flow** based on `main`.

* **main branch**: Always releasable. Direct commits are forbidden; use pull requests.
* **Feature branches (`feature/<topic>`)**: Branch from `main` for new features or enhancements, then open a PR when done.
* **Hotfix branches (`hotfix/<issue>`)**: Branch from `main` for urgent fixes, merge promptly after CI passes.

### Rules

* Always branch from `main`.
* Assign reviewers when opening a PR and merge only after CI passes.
* Feel free to delete branches after merging.

---


## 10. Commit Message Policy

Commit messages follow **Conventional Commits**. Agents must comply. Write the comment section in **English**.

### Format

```
type(scope?): description
```

* `type`: feat / fix / docs / style / refactor / test / chore
* `scope`: Optional; module or directory names, etc.
* `description`: Describe the change concisely in English.

### Body

* Write the WHY (reason for the change) in a single English sentence.
* List the HOW (per-file changes) in English.

```
- src/lib.rs: Optimized setting loading process
- docs/setup.md: Update the initial setup procedure
```

### Granularity

* Default to one semantic change per commit.
* Separate generated code into logical units; do not mix with other changes.

### PRs and Commits

* Always document **Motivation / Design / Tests / Risks** in English in the PR description.
* Follow team policy on squashing after reviews; if none, keep the original commit structure.

---

## 11. Documentation Policy

* **README.md (top level)**:
  * Introduction: tool overview, usage, installation.
  * Later sections: developer build steps, testing instructions.
  * Keep it accessible so first-time users can onboard smoothly.

* **docs/**:
  * Create detailed designs or supplemental docs as needed. None exist yet, so define structure and filenames when adding.

* **Operational Guidelines**:
  * Update documentation alongside code changes; if none are needed, note "No documentation changes" in the PR description.
  * Verify sample code and command examples actually work.
  * Include generation scripts when submitting auto-generated docs.

---

## 12. Dependency Management Policy

* Add dependencies with `cargo add <crate>`; do not edit Cargo.toml by hand for adds.
* Use SemVer pins; avoid wildcards unless necessary.
* Update dependencies per-PR with `cargo update -p <crate>`, explaining the target and reason.
* Run `cargo audit` for PRs to ensure no known vulnerabilities.
* Limit **dev-dependencies** to tests/tooling; remove when unused. Keep **build-dependencies** minimal and justify large additions.

---

## 13. Release Process

* Follow **SemVer** for versioning.
* Tag new releases with `git tag vX.Y.Z` and verify `make release` outputs.
* Update CHANGELOG.md and reflect the changes in the release notes (include generators in the PR if they were used).

### 13.1 CHANGELOG.md Policy

* **Sections**: Follow `[Keep a Changelog]` categories - `Added / Changed / Fixed / Deprecated / Removed / Security`.
* **Language**: English.
* **Writing Principles**:
  * Describe "what changes for the user" in one sentence; include implementation details only when needed.
  * Emphasize **breaking changes** in bold and provide migration steps.
  * Include PR/Issue numbers when possible (e.g., `(#123)`).
* **Workflow**:
  1. Add entries to the `Unreleased` section in feature PRs.
  2. Update the version number and date in release PRs.
  3. After tagging, copy the relevant section into the release notes.
* **Links (recommended)**:
  * Add comparison links at the end of the file.
* **Supporting Tools** (optional):
  * Use tools like `git-cliff` or `conventional-changelog` to draft entries, then edit manually.

---

## 14. PR Template

Include the following items when creating a PR:

* **Motivation**: Why this change is needed.
* **Design**: How you implemented it.
* **Tests**: Which tests were run.
* **Risks**: Potential side effects or concerns.

Template example:

```
### Motivation
...

### Design
...

### Tests
...

### Risks
...
```

---

## 15. Checklist

* [ ] `make lint`
* [ ] `make test`
* [ ] `make build`