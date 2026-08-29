import pytest

from assureops import frameworks as fw
from assureops.errors import FrameworkError


class TestResolution:
    def test_resolves_known_control(self):
        assert fw.resolve("A.5.19").title.startswith("Information security in supplier")

    def test_unknown_control_raises_with_the_id(self):
        with pytest.raises(FrameworkError, match="A.99.9"):
            fw.resolve("A.99.9")

    def test_validate_all_sorts_and_deduplicates(self):
        assert fw.validate_all(["A.8.8", "A.5.15", "A.8.8"]) == ("A.5.15", "A.8.8")


class TestCsfMapping:
    def test_supplier_controls_map_to_govern(self):
        assert fw.csf_function("A.5.19") == "Govern"

    def test_vulnerability_management_maps_to_identify(self):
        assert fw.csf_function("A.8.8") == "Identify"

    def test_incident_management_maps_to_respond(self):
        assert fw.csf_function("A.5.24") == "Respond"

    def test_every_control_has_a_mapping(self):
        for control_id in fw.ISO_27001_ANNEX_A:
            assert fw.csf_function(control_id) in fw.NIST_CSF_FUNCTIONS.values()

    def test_csf_two_includes_govern(self):
        """GOVERN was introduced in CSF 2.0 and must be present."""
        assert "GV" in fw.NIST_CSF_FUNCTIONS

    def test_unmapped_control_raises(self):
        with pytest.raises(FrameworkError):
            fw.csf_function("A.99.9")


class TestCoverage:
    def test_counts_by_function(self):
        counts = fw.coverage_by_function(["A.5.19", "A.5.20", "A.8.8"])
        assert counts["Govern"] == 2 and counts["Identify"] == 1

    def test_all_functions_present_even_when_zero(self):
        counts = fw.coverage_by_function(["A.5.19"])
        assert set(counts) == set(fw.NIST_CSF_FUNCTIONS.values())

    def test_counts_by_theme(self):
        counts = fw.coverage_by_theme(["A.8.2", "A.8.5", "A.5.19"])
        assert counts["Technological"] == 2 and counts["Organisational"] == 1

    def test_empty_input_is_handled(self):
        assert sum(fw.coverage_by_function([]).values()) == 0
