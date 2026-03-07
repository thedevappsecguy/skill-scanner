from __future__ import annotations

from skill_scanner.models.findings import (
    Category,
    canonicalize_category,
    observed_pattern_specs_for_prompt,
)


def test_observed_pattern_specs_for_prompt_include_expected_categories() -> None:
    categories = [item.category for item in observed_pattern_specs_for_prompt()]
    assert categories == [
        Category.EXTERNAL_DOWNLOAD,
        Category.PROMPT_INJECTION,
        Category.SSRF_CLOUD,
        Category.COMMAND_EXECUTION,
        Category.SUPPLY_CHAIN,
        Category.EXFILTRATION,
        Category.CREDENTIAL_LEAK,
        Category.INDIRECT_INJECTION,
        Category.TOXIC_FLOW,
        Category.THIRD_PARTY_CONTENT,
    ]


def test_canonicalize_category_maps_legacy_aliases() -> None:
    assert canonicalize_category("data_exfiltration") == Category.EXFILTRATION
    assert canonicalize_category("hidden_commands") == Category.COMMAND_EXECUTION
    assert canonicalize_category("credential_harvesting") == Category.CREDENTIAL_LEAK
    assert canonicalize_category("supply_chain_risk") == Category.SUPPLY_CHAIN


def test_canonicalize_category_handles_hyphenated_values() -> None:
    assert canonicalize_category("external-download") == Category.EXTERNAL_DOWNLOAD
    assert canonicalize_category("third-party-content") == Category.THIRD_PARTY_CONTENT


def test_canonicalize_category_unknown_falls_back_to_configuration_risk() -> None:
    assert canonicalize_category("unknown_category") == Category.CONFIGURATION_RISK
