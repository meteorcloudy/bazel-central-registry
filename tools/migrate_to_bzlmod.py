#!/usr/bin/env python3
#
# Copyright 2021 The Bazel Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# ...

import argparse
import importlib.util
import json
import locale
import pathlib
import re
import subprocess
import sys
import tempfile
import os
from urllib.parse import urlparse
import logging

from registry import RegistryClient

# Configure logging with colored output
class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.INFO: "\x1b[32m",     # Green
        logging.WARNING: "\x1b[33m",  # Yellow
        logging.ERROR: "\x1b[31m",    # Red
    }
    RESET = "\x1b[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        reset = self.RESET
        levelname = record.levelname
        prefix = f"{color}{levelname}:{reset}"
        message = record.getMessage()
        return f"{prefix} {message}"

handler = logging.StreamHandler()
handler.setFormatter(ColoredFormatter('%(message)s'))
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Global variable to store the Bazel version
BAZEL_VERSION = None

# The registry client points to the bazel central registry repo
REGISTRY_CLIENT = RegistryClient(pathlib.Path(__file__).parent.parent)

USE_REPO_RULE_IDENTIFIER = "# -- use_repo_rule statements -- #"
LOAD_IDENTIFIER = "# -- load statements -- #"
REPO_IDENTIFIER = "# -- repo definitions -- #"
BAZEL_DEP_IDENTIFIER = "# -- bazel_dep definitions -- #"

def abort_migration():
    """Abort the migration process."""
    logger.info("Abort migration...")
    sys.exit(2)

def assert_exit_code(exit_code, expected_exit_code, error_message, stderr):
    """Assert that the command exited with the expected exit code."""
    if exit_code != expected_exit_code:
        logger.error(f"Command exited with {exit_code}, expected {expected_exit_code}:")
        logger.error(stderr)
        abort_migration()

def ask_input(msg):
    """Prompt the user for input with a message."""
    YELLOW = "\x1b[33m"
    RESET = "\x1b[0m"
    return input(f"{YELLOW}ACTION: {RESET}{msg}")

def yes_or_no(question, default, interactive):
    """Prompt the user with a yes/no question."""
    if not interactive:
        return default

    prompt = f"{question} [{'Y/n' if default else 'y/N'}]: "
    while True:
        user_input = ask_input(prompt).strip().lower()
        if user_input == "y":
            return True
        elif user_input == "n":
            return False
        elif not user_input:
            return default
        else:
            logger.error(f"Invalid selection: {user_input}")

def scratch_file(file_path, lines=None, mode="w"):
    """Write lines to a file."""
    abspath = pathlib.Path(file_path)
    with open(abspath, mode) as f:
        if lines:
            for line in lines:
                f.write(line)
                f.write("\n")
    return abspath

def execute_command(args, cwd=None, env=None, shell=False, executable=None):
    """Execute a command and capture its output."""
    logger.info(f"Executing command: {' '.join(args)}")
    result = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
        shell=shell,
        executable=executable,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr

def print_repo_definition(dep):
    """Print the repository info and return the repository definition."""
    # Parse the repository rule class
    rule_class = dep["original_rule_class"]
    if "%" in rule_class:
        # Starlark rule
        file_label, rule_name = rule_class.split("%")
        if rule_name.startswith("_"):
            def_info = dep["definition_information"].split("\n")
            def_info.reverse()
            for line in def_info:
                s = re.match(r"^  (.+):[0-9]+:[0-9]+: in ([^\_<].+)$", line)
                if s:
                    new_file_name, new_rule_name = s.groups()
                    if new_file_name.endswith(file_label.split("//")[1].replace(":", "/")):
                        rule_name = new_rule_name
                    else:
                        logger.warning(
                            f"A visible macro for {rule_name} is defined in a different bzl file `{new_file_name}` "
                            f"other than `{file_label}`. You have to find the correct label manually."
                        )
                    break
    else:
        # Native rule
        file_label = None
        rule_name = rule_class

    # Generate the repository definition lines
    repo_def = []
    if file_label:
        repo_def.append(f'load("{file_label}", "{rule_name}")')
    repo_def.append(f"{rule_name}(")
    for key, value in dep["original_attributes"].items():
        if not key.startswith("generator_"):
            value_str = json.dumps(value, indent=4)
            if value_str.endswith("}") or value_str.endswith("]"):
                value_str = value_str[:-1] + "  " + value_str[-1]
            if value_str.lower() in ["false", "true"]:
                value_str = value_str.capitalize()
            repo_def.append(f"  {key} = {value_str},")
    repo_def.append(")")

    header = f"----- Repository information for @{dep['original_attributes']['name']} in the WORKSPACE file -----"
    logger.info(header)
    if "definition_information" in dep:
        logger.info(dep["definition_information"])
    logger.info("Repository definition:")
    for line in repo_def:
        logger.info(line)
    logger.info("-" * len(header))

    if file_label and file_label.startswith("@@"):
        file_label = file_label[1:]

    return repo_def, file_label, rule_name

def detect_unavailable_repo_error(stderr):
    """Detect missing repository errors and extract the missing repository name."""
    patterns = [
        re.compile(r"unknown repo '([A-Za-z0-9_-]+)' requested from"),
        re.compile(r"The repository '@([A-Za-z0-9_-]+)' could not be resolved"),
        re.compile(r"No repository visible as '@([A-Za-z0-9_-]+)' from main repository"),
        re.compile(r"This could either mean you have to add the '@([A-Za-z0-9_-]+)' repository"),
    ]

    for line in stderr.split("\n"):
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                logger.error(line)
                return match.group(1)
    return None

def write_at_given_place(filename, new_content, identifier):
    """Write content to a file at a position marked by the identifier."""
    with open(filename, "r") as f:
        file_content = f.read()
    file_content = file_content.replace(
        identifier,
        new_content + "\n" + identifier,
        1,
    )
    with open(filename, "w") as f:
        f.write(file_content)

def add_repo_with_use_repo_rule(repo, repo_def, file_label, rule_name):
    """Introduce a repository with use_repo_rule in the MODULE.bazel file."""
    logger.info(f"Introducing @{repo} via use_repo_rule.")
    use_repo_rule = f'{rule_name} = use_repo_rule("{file_label}", "{rule_name}")'

    with open("MODULE.bazel", "r") as f:
        module_content = f.read()
    if use_repo_rule not in module_content:
        write_at_given_place("MODULE.bazel", use_repo_rule, USE_REPO_RULE_IDENTIFIER)

    write_at_given_place(
        "MODULE.bazel",
        "\n".join([""] + repo_def[1:]),
        REPO_IDENTIFIER,
    )

def add_repo_to_module_extension(repo, repo_def, file_label, rule_name):
    """Introduce a repository via a module extension."""
    logger.info(f"Introducing @{repo} via a module extension.")

    need_separate_module_extension = not file_label.startswith("@bazel_tools")
    ext_name = f"extension_for_{rule_name}".replace("-", "_") if need_separate_module_extension else "non_module_deps"
    ext_bzl_name = f"{ext_name}.bzl"

    if not pathlib.Path(ext_bzl_name).is_file():
        scratch_file(
            ext_bzl_name,
            [
                LOAD_IDENTIFIER,
                "",
                f"def _{ext_name}_impl(ctx):",
                REPO_IDENTIFIER,
                "",
                f"{ext_name} = module_extension(implementation = _{ext_name}_impl)",
            ],
        )

    load_statement = f'load("{file_label}", "{rule_name}")'
    with open(ext_bzl_name, "r") as f:
        bzl_content = f.read()
    if load_statement not in bzl_content:
        write_at_given_place(ext_bzl_name, load_statement, LOAD_IDENTIFIER)
    write_at_given_place(
        ext_bzl_name,
        "\n".join(["  " + line.replace("\n", "\n  ") for line in repo_def[1:]]),
        REPO_IDENTIFIER,
    )

    use_ext = f'{ext_name} = use_extension("//:{ext_name}.bzl", "{ext_name}")'
    with open("MODULE.bazel", "r") as f:
        module_content = f.read()
    ext_identifier = f"# End of extension `{ext_name}`"
    if use_ext not in module_content:
        scratch_file("MODULE.bazel", ["", use_ext, ext_identifier], mode="a")
    write_at_given_place("MODULE.bazel", f'use_repo({ext_name}, "{repo}")', ext_identifier)

def url_match_source_repo(source_url, module_name):
    """Check if the source URL matches any of the module's source repositories."""
    source_repositories = REGISTRY_CLIENT.get_metadata(module_name).get("repository", [])
    matched = False
    parts = urlparse(source_url)
    for source_repository in source_repositories:
        if matched:
            break
        repo_type, repo_path = source_repository.split(":")
        if repo_type == "github":
            matched = (
                parts.scheme == "https"
                and parts.netloc == "github.com"
                and (
                    os.path.abspath(parts.path).startswith(f"/{repo_path}/")
                    or os.path.abspath(parts.path).startswith(f"/{repo_path}.git")
                )
            )
        elif repo_type == "https":
            repo = urlparse(source_repository)
            matched = (
                parts.scheme == repo.scheme
                and parts.netloc == repo.netloc
                and os.path.abspath(parts.path).startswith(f"{repo.path}/")
            )
    return matched

def address_unavailable_repo_error(repo, resolved_deps, workspace_name, interactive):
    """Handle errors caused by unavailable repositories."""
    logger.error(f"@{repo} is not visible in the Bzlmod build.")

    if repo == workspace_name:
        logger.error(
            f"Please remove the usages of referring your own repo via `@{repo}//`. "
            "Targets should be referenced directly with `//`."
        )
        logger.error(
            'If it\'s used in a macro, you can use `Label("//foo/bar")` '
            "to ensure it always points to your repo."
        )
        logger.error(
            "You can temporarily work around this by adding `repo_name` attribute "
            "to the `module` directive in your MODULE.bazel file."
        )
        abort_migration()

    repo_def, file_label, rule_name = [], None, None
    urls = []
    for dep in resolved_deps:
        if dep["original_attributes"]["name"] == repo:
            repo_def, file_label, rule_name = print_repo_definition(dep)
            urls.extend(dep["original_attributes"].get("urls", []))
            if dep["original_attributes"].get("url"):
                urls.append(dep["original_attributes"]["url"])
            if dep["original_attributes"].get("remote"):
                urls.append(dep["original_attributes"]["remote"])
            break
    if not repo_def:
        logger.error(
            f"Repository definition for {repo} isn't found in ./resolved_deps.py file. "
            "Please add `--force/-f` flag to force update it."
        )
        abort_migration()

    logger.info(f"Searching for Bazel module based on repo name ({repo}) and URLs: {urls}")
    found_module = None
    for module_name in REGISTRY_CLIENT.get_all_modules():
        if repo == module_name or any(url_match_source_repo(url, module_name) for url in urls):
            found_module = module_name

    if found_module:
        metadata = REGISTRY_CLIENT.get_metadata(found_module)
        version = metadata["versions"][-1]
        repo_name = "" if repo == found_module else f', repo_name = "{repo}"'
        bazel_dep_line = f'bazel_dep(name = "{found_module}", version = "{version}"{repo_name})'
        logger.info(f"Found module `{found_module}` in the registry, available versions: {metadata['versions']}")
        logger.info(f"This can be introduced via a bazel_dep definition:")
        logger.info(f"    {bazel_dep_line}")

        if yes_or_no(
            "Do you wish to add the bazel_dep definition to the MODULE.bazel file?",
            True,
            interactive,
        ):
            logger.info(f"Introducing @{repo} as a Bazel module.")
            write_at_given_place("MODULE.bazel", bazel_dep_line, BAZEL_DEP_IDENTIFIER)
            return True
    else:
        logger.info(f"{repo} isn't found in the registry.")

    if (
        file_label
        and file_label.startswith(("//", "@bazel_tools//"))
        and yes_or_no(
            "Do you wish to introduce the repository with use_repo_rule in MODULE.bazel (requires Bazel 7.3 or later)?",
            True,
            interactive,
        )
    ):
        add_repo_with_use_repo_rule(repo, repo_def, file_label, rule_name)
    elif file_label and yes_or_no("Do you wish to introduce the repository with a module extension?", True, interactive):
        add_repo_to_module_extension(repo, repo_def, file_label, rule_name)
    elif yes_or_no(
        "Do you wish to add the repo definition to WORKSPACE.bzlmod for later migration?",
        True,
        interactive,
    ):
        repo_def = ["", "# TODO: Migrated to Bzlmod"] + repo_def
        logger.info(f"Introducing @{repo} in WORKSPACE.bzlmod file.")
        scratch_file("WORKSPACE.bzlmod", repo_def, mode="a")
    else:
        logger.info("Please manually add this dependency ...")
        abort_migration()
    return True

def detect_bind_issue(stderr):
    """Detect errors that may be caused by missing bind statements."""
    for line in stderr.split("\n"):
        match = re.search(r"no such target '(//external:[A-Za-z0-9_-]+)'", line)
        if match:
            logger.error(line)
            return match.group(1)
    return None

def address_bind_issue(bind_target, resolved_repos, interactive):
    """Handle errors caused by missing bind statements."""
    logger.warning(
        f"A bind target detected: {bind_target}! `bind` is deprecated. "
        "You should reference the actual target directly instead of using //external:<target>."
    )

    name = bind_target.split(":")[1]
    bind_def = None
    for dep in resolved_repos:
        if dep["original_rule_class"] == "bind" and dep["original_attributes"]["name"] == name:
            bind_def, _, _ = print_repo_definition(dep)
            break

    if bind_def:
        bind_def = ["", "# TODO: Remove the following bind usage"] + bind_def
        if yes_or_no(
            "Do you wish to add the bind definition to WORKSPACE.bzlmod for later migration?",
            True,
            interactive,
        ):
            logger.info(f"Adding bind statement for {bind_target} in WORKSPACE.bzlmod")
            scratch_file("WORKSPACE.bzlmod", bind_def, mode="a")
            return True
    else:
        logger.warning(
            f"Bind definition for {bind_target} isn't found in ./resolved_deps.py file. Please fix manually. "
            "You can get more verbose info by rerunning the script with --sync/-s and --force/-f flags."
        )
        abort_migration()

def extract_version_number(bazel_version):
    """Extracts the semantic version number from a version string."""
    for i, c in enumerate(bazel_version):
        if not (c.isdigit() or c == "."):
            return bazel_version[:i]
    return bazel_version

def parse_bazel_version(bazel_version):
    """Parses a version string into a 3-tuple of ints."""
    if bazel_version == "no_version":
        logger.warning(
            "Current bazel is not a release version. We recommend using Bazel 7 or newer releases for Bzlmod migration."
        )
        return (999, 999, 999)

    version = extract_version_number(bazel_version)
    return tuple(int(n) for n in version.split("."))

def get_bazel_version():
    """Get the Bazel version and store it in the global variable."""
    global BAZEL_VERSION
    exit_code, stdout, _ = execute_command(["bazel", "--version"])
    logger.info(stdout.strip())
    bazel_version_str = stdout.strip().split(" ")[1]
    BAZEL_VERSION = parse_bazel_version(bazel_version_str)
    if BAZEL_VERSION < (7, 0, 0):
        logger.error("Current Bazel version is too old. Please upgrade to Bazel 7 or newer releases for Bzlmod migration.")
        abort_migration()

def prepare_migration():
    """Preparation work before starting the migration."""
    get_bazel_version()

    workspace_name = "main"
    workspace_file = "WORKSPACE.bazel" if pathlib.Path("WORKSPACE.bazel").is_file() else "WORKSPACE"

    with open(workspace_file, "r") as f:
        for line in f:
            match = re.search(r"workspace\(name\s+=\s+['\"]([A-Za-z0-9_-]+)['\"]", line)
            if match:
                workspace_name = match.group(1)
                logger.info(f"Detected original workspace name: {workspace_name}")

    if not pathlib.Path("MODULE.bazel").is_file():
        scratch_file(
            "MODULE.bazel",
            [f'module(name = "{workspace_name}", version="")'],
        )
    with open("MODULE.bazel", "r") as f:
        module_content = f.read()
    for identifier in [
        BAZEL_DEP_IDENTIFIER,
        USE_REPO_RULE_IDENTIFIER,
        REPO_IDENTIFIER,
    ]:
        if identifier not in module_content:
            scratch_file("MODULE.bazel", ["", identifier], mode="a")

    scratch_file("WORKSPACE.bzlmod", [], mode="a")

    return workspace_name

def generate_resolved_file(targets, use_bazel_sync):
    """Generate the resolved dependencies file."""
    exit_code, _, stderr = execute_command(["bazel", "clean", "--expunge"])
    assert_exit_code(exit_code, 0, "Failed to run `bazel clean --expunge`", stderr)
    bazel_command = [
        "bazel",
        "sync" if use_bazel_sync else "build",
        "--enable_workspace",
        "--experimental_repository_resolved_file=resolved_deps.py",
    ] + (["--nobuild"] if not use_bazel_sync else []) + targets
    exit_code, _, stderr = execute_command(bazel_command)
    assert_exit_code(exit_code, 0, f"Failed to run `{' '.join(bazel_command)}`", stderr)

    with open("resolved_deps.py", "r") as f:
        lines = f.readlines()
    with open("resolved_deps.py", "w") as f:
        for line in lines:
            if '"_action_listener":' not in line:
                f.write(line)

def load_resolved_deps(targets, use_bazel_sync, force):
    """Generate and load the resolved file containing external dependencies."""
    if not pathlib.Path("resolved_deps.py").is_file() or force:
        logger.info("Generating ./resolved_deps.py file")
        generate_resolved_file(targets, use_bazel_sync)
    else:
        logger.info(
            "Found existing ./resolved_deps.py file. "
            "If it's out of date, please add `--force/-f` flag to force update it."
        )

    spec = importlib.util.spec_from_file_location("resolved_deps", "./resolved_deps.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["resolved_deps"] = module
    spec.loader.exec_module(module)
    resolved_deps = module.resolved
    logger.info(f"Found {len(resolved_deps)} external repositories in the ./resolved_deps.py file.")
    return resolved_deps

def main(argv=None):
    """Main function."""
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="migrate_to_bzlmod",
        description=(
            "A helper script for migrating your external dependencies from WORKSPACE to Bzlmod. "
            "For given targets, it first tries to generate a list of external dependencies for building your targets, "
            "then tries to detect and add missing dependencies in the Bzlmod build. "
            "You may still need to fix some problems manually."
        ),
        epilog=(
            "Example usage: change into your project directory and run "
            "`<path to BCR repo>/tools/migrate_to_bzlmod.py --target //foo:bar`"
        ),
    )
    parser.add_argument(
        "-s",
        "--sync",
        action="store_true",
        help=(
            "Use `bazel sync` instead of `bazel build --nobuild` to generate the resolved dependencies. "
            "`bazel build --nobuild` only fetches dependencies needed for building specified targets, "
            "while `bazel sync` resolves and fetches all dependencies defined in your WORKSPACE file."
        ),
    )
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Ignore previously generated resolved dependencies.",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Ask the user interactively on what to do.",
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="Specify the targets you want to migrate. This flag is repeatable.",
    )

    args = parser.parse_args(argv)

    if not args.target:
        parser.print_help()
        return 1

    workspace_name = prepare_migration()
    resolved_deps = load_resolved_deps(args.target, args.sync, args.force)
    interactive = args.interactive

    while True:
        bazel_command = [
            "bazel",
            "build",
            "--nobuild",
            "--enable_bzlmod",
            "--noenable_workspace",
        ] + args.target
        exit_code, _, stderr = execute_command(bazel_command)
        if exit_code == 0:
            logger.info(
                f"Congratulations! All external repositories needed for building `{' '.join(args.target)}` are available with Bzlmod!"
            )
            logger.info("Next steps:")
            logger.info("  - Migrate remaining dependencies in the WORKSPACE.bzlmod file to Bzlmod.")
            logger.info(
                "  - Run the actual build with Bzlmod enabled (with --enable_bzlmod, but without --nobuild) "
                "and fix any remaining build-time issues."
            )
            break

        repo = detect_unavailable_repo_error(stderr)
        if repo:
            if address_unavailable_repo_error(repo, resolved_deps, workspace_name, interactive):
                continue
            else:
                abort_migration()

        bind_target = detect_bind_issue(stderr)
        if bind_target:
            if address_bind_issue(bind_target, resolved_deps, interactive):
                continue
            else:
                abort_migration()

        logger.error("Unrecognized error, please fix manually:\n" + stderr)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
