import importlib.util
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "security" / "generate_custom_python_vex.py"


def load_module():
    spec = importlib.util.spec_from_file_location("generate_custom_python_vex", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_extract_cves_from_manifest_preserves_patch_order():
    module = load_module()

    manifest = {
        "patches": [
            {"name": "0004-cve-2026-1502-http-tunnel-header-validation.patch"},
            {"name": "0006-cve-2025-15367-pop-control-char-rejection.patch"},
            {"name": "0005-cve-2025-15366-imap-control-char-rejection.patch"},
            {"name": "readme-only-note.patch"},
            {"name": "0007-cve-2025-12781-strict-altchar-base64-decoding.patch"},
        ]
    }

    assert module.extract_cves_from_manifest(manifest) == (
        "CVE-2026-1502",
        "CVE-2025-15367",
        "CVE-2025-15366",
        "CVE-2025-12781",
    )


def test_build_vex_document_uses_exact_image_refs_and_python_subcomponents():
    module = load_module()

    images = [
        module.ImageBuildMetadata(
            image_ref="secai-sandbox-ui:latest",
            python_version="3.14.4",
            cves=("CVE-2026-1502", "CVE-2025-12781"),
        ),
        module.ImageBuildMetadata(
            image_ref="secai-sandbox-agent:latest",
            python_version="3.14.4",
            cves=("CVE-2026-1502",),
        ),
    ]

    document = module.build_vex_document(
        images,
        author="SecAI OS",
        role="Vendor",
        document_id="https://secai.local/vex/test",
        timestamp="2026-04-24T06:20:00Z",
    )

    assert document["@id"] == "https://secai.local/vex/test"
    assert document["timestamp"] == "2026-04-24T06:20:00Z"
    assert [statement["vulnerability"]["name"] for statement in document["statements"]] == [
        "CVE-2025-12781",
        "CVE-2026-1502",
    ]

    cve_1502 = next(
        statement
        for statement in document["statements"]
        if statement["vulnerability"]["name"] == "CVE-2026-1502"
    )
    assert cve_1502["status"] == "not_affected"
    assert cve_1502["products"] == [
        {
            "@id": "secai-sandbox-ui:latest",
            "subcomponents": [{"@id": "pkg:generic/python@3.14.4"}],
        },
        {
            "@id": "secai-sandbox-agent:latest",
            "subcomponents": [{"@id": "pkg:generic/python@3.14.4"}],
        },
    ]


def test_collect_image_build_metadata_reads_manifest_from_each_image():
    module = load_module()

    manifests = {
        "secai-sandbox-ui:latest": """{
  "upstream_version": "3.14.4",
  "patches": [
    {"name": "0001-cve-2026-4786-webbrowser-action-bypass.patch"},
    {"name": "0002-cve-2026-6100-decompressor-uaf.patch"}
  ]
}""",
        "secai-sandbox-search-mediator:latest": """{
  "upstream_version": "3.14.4",
  "patches": [
    {"name": "0001-cve-2026-4786-webbrowser-action-bypass.patch"},
    {"name": "0002-cve-2026-6100-decompressor-uaf.patch"},
    {"name": "0004-cve-2026-1502-http-tunnel-header-validation.patch"}
  ]
}""",
    }

    def fake_run_command(args):
        image_ref = args[5]
        return manifests[image_ref]

    metadata = module.collect_image_build_metadata(
        image_refs=list(manifests),
        command_runner=fake_run_command,
    )

    assert metadata == [
        module.ImageBuildMetadata(
            image_ref="secai-sandbox-ui:latest",
            python_version="3.14.4",
            cves=("CVE-2026-4786", "CVE-2026-6100"),
        ),
        module.ImageBuildMetadata(
            image_ref="secai-sandbox-search-mediator:latest",
            python_version="3.14.4",
            cves=("CVE-2026-4786", "CVE-2026-6100", "CVE-2026-1502"),
        ),
    ]


def test_collect_unicode_locale_glibc_metadata_uses_exact_apk_purl():
    module = load_module()

    inspections = {
        "secai-sandbox-ui:latest": """{
  "lang": "C.UTF-8",
  "lc_all": "C.UTF-8",
  "preferred_encoding": "UTF-8",
  "ctype_locale": "C.UTF-8",
  "locale_error": null,
  "glibc_version": null,
  "arch": "x86_64",
  "os_release": {"ID": "wolfi", "VERSION_ID": "20230201"}
}""",
        "secai-sandbox-diffusion:latest": """{
  "lang": "C.UTF-8",
  "lc_all": "C.UTF-8",
  "preferred_encoding": "UTF-8",
  "ctype_locale": "C.UTF-8",
  "locale_error": null,
  "glibc_version": "2.43-r6",
  "arch": "x86_64",
  "os_release": {"ID": "wolfi", "VERSION_ID": "20230201"}
}""",
    }

    def fake_run_command(args):
        image_ref = args[5]
        return inspections[image_ref]

    metadata = module.collect_unicode_locale_glibc_metadata(
        image_refs=list(inspections),
        command_runner=fake_run_command,
    )

    assert metadata == [
        module.UnicodeLocaleGlibcMetadata(
            image_ref="secai-sandbox-diffusion:latest",
            package_purl="pkg:apk/wolfi/glibc@2.43-r6?arch=x86_64&distro=wolfi-20230201",
        )
    ]


def test_build_vex_document_can_include_unicode_locale_glibc_statement():
    module = load_module()

    images = [
        module.ImageBuildMetadata(
            image_ref="secai-sandbox-diffusion:latest",
            python_version="3.14.4",
            cves=("CVE-2026-1502",),
        ),
    ]
    glibc_statement = module.build_unicode_locale_glibc_statement(
        module.UnicodeLocaleGlibcMetadata(
            image_ref="secai-sandbox-diffusion:latest",
            package_purl="pkg:apk/wolfi/glibc@2.43-r6?arch=x86_64&distro=wolfi-20230201",
        ),
        timestamp="2026-04-24T06:20:00Z",
    )

    document = module.build_vex_document(
        images,
        author="SecAI OS",
        role="Vendor",
        document_id="https://secai.local/vex/test",
        timestamp="2026-04-24T06:20:00Z",
        extra_statements=[glibc_statement],
    )

    assert [statement["vulnerability"]["name"] for statement in document["statements"]] == [
        "CVE-2026-1502",
        "CVE-2026-5928",
    ]
    glibc_cve = next(
        statement
        for statement in document["statements"]
        if statement["vulnerability"]["name"] == "CVE-2026-5928"
    )
    assert glibc_cve["justification"] == "inline_mitigations_already_exist"
    assert glibc_cve["products"] == [
        {
            "@id": "secai-sandbox-diffusion:latest",
            "subcomponents": [
                {"@id": "pkg:apk/wolfi/glibc@2.43-r6?arch=x86_64&distro=wolfi-20230201"}
            ],
        }
    ]
