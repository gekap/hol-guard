"""Regression coverage for provider registry path containment."""

from codex_plugin_scanner.guard.runtime import isolation_provider as isolation_provider_module


def test_provider_path_containment_uses_root_path_flavor() -> None:
    windows_root = r"C:\ProgramData\HOL Guard\providers"
    assert isolation_provider_module._path_is_within(
        r"C:\ProgramData\HOL Guard\providers\oci-isolation.py", windows_root
    )
    assert isolation_provider_module._path_is_within(
        r"c:\programdata\hol guard\PROVIDERS\oci-isolation.py", windows_root
    )
    assert not isolation_provider_module._path_is_within(
        r"C:\ProgramData\HOL Guard\providers-evil\oci-isolation.py", windows_root
    )
    assert not isolation_provider_module._path_is_within(
        r"D:\ProgramData\HOL Guard\providers\oci-isolation.py", windows_root
    )
    posix_root = "/usr/libexec/hol-guard/providers"
    assert isolation_provider_module._path_is_within(f"{posix_root}/seatbelt", posix_root)
    assert not isolation_provider_module._path_is_within(f"{posix_root}-evil/seatbelt", posix_root)
