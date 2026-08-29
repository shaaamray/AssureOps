import json

import pytest

from assureops import ingest
from assureops.errors import ValidationError
from assureops.models import DataClass

VENDOR_CSV = """vendor_id,name,service,data_class,business_critical,domain
v-1,Alpha,Claims,restricted,true,alpha.example
v-2,Beta,Print,internal,false,
"""

ENTITLEMENT_CSV = """principal,system,role,privileged,days_since_login,last_reviewed_days,enabled,mfa_enrolled
a@example.com,ERP,admin,true,10,30,true,true
b@example.com,CRM,user,false,,,,
"""


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestVendors:
    def test_loads_csv(self, tmp_path):
        vendors = ingest.load_vendors(write(tmp_path, "v.csv", VENDOR_CSV))
        assert len(vendors) == 2
        assert vendors[0].data_class is DataClass.RESTRICTED

    def test_boolean_parsing(self, tmp_path):
        vendors = ingest.load_vendors(write(tmp_path, "v.csv", VENDOR_CSV))
        assert vendors[0].business_critical is True
        assert vendors[1].business_critical is False

    def test_blank_domain_becomes_none(self, tmp_path):
        assert ingest.load_vendors(write(tmp_path, "v.csv", VENDOR_CSV))[1].domain is None

    def test_loads_json(self, tmp_path):
        payload = [{"vendor_id": "v-1", "name": "Alpha", "service": "s",
                    "data_class": "internal", "business_critical": False}]
        path = write(tmp_path, "v.json", json.dumps(payload))
        assert ingest.load_vendors(path)[0].vendor_id == "v-1"

    def test_missing_column_names_the_row(self, tmp_path):
        with pytest.raises(ValidationError, match="row 1"):
            ingest.load_vendors(write(tmp_path, "v.csv", "vendor_id,name\nv-1,Alpha\n"))

    def test_invalid_data_class_is_reported(self, tmp_path):
        bad = "vendor_id,name,service,data_class,business_critical\nv-1,A,s,ultra-secret,false\n"
        with pytest.raises(ValidationError):
            ingest.load_vendors(write(tmp_path, "v.csv", bad))

    def test_missing_file_is_reported(self, tmp_path):
        with pytest.raises(ValidationError, match="not found"):
            ingest.load_vendors(tmp_path / "absent.csv")

    def test_json_must_be_an_array(self, tmp_path):
        with pytest.raises(ValidationError, match="array"):
            ingest.load_vendors(write(tmp_path, "v.json", '{"not": "a list"}'))


class TestEntitlements:
    def test_loads_csv(self, tmp_path):
        ents = ingest.load_entitlements(write(tmp_path, "e.csv", ENTITLEMENT_CSV))
        assert len(ents) == 2 and ents[0].privileged is True

    def test_blank_numerics_become_none(self, tmp_path):
        ents = ingest.load_entitlements(write(tmp_path, "e.csv", ENTITLEMENT_CSV))
        assert ents[1].days_since_login is None

    def test_enabled_defaults_to_true_when_blank(self, tmp_path):
        ents = ingest.load_entitlements(write(tmp_path, "e.csv", ENTITLEMENT_CSV))
        assert ents[1].enabled is True

    def test_non_numeric_day_count_is_rejected(self, tmp_path):
        bad = ENTITLEMENT_CSV.replace(",10,", ",soon,")
        with pytest.raises(ValidationError, match="integer"):
            ingest.load_entitlements(write(tmp_path, "e.csv", bad))


class TestAnswers:
    def test_long_format_csv_is_pivoted_by_vendor(self, tmp_path):
        csv_text = ("vendor_id,question_id,answer\n"
                    "v-1,GOV-01,yes\nv-1,IAM-01,no\nv-2,GOV-01,partial\n")
        answers = ingest.load_answers(write(tmp_path, "a.csv", csv_text))
        assert answers["v-1"] == {"GOV-01": "yes", "IAM-01": "no"}
        assert answers["v-2"]["GOV-01"] == "partial"

    def test_json_object_is_used_directly(self, tmp_path):
        payload = {"v-1": {"GOV-01": "yes"}}
        assert ingest.load_answers(write(tmp_path, "a.json", json.dumps(payload))) == payload

    def test_json_must_be_an_object(self, tmp_path):
        with pytest.raises(ValidationError, match="object"):
            ingest.load_answers(write(tmp_path, "a.json", "[1,2]"))


class TestFindings:
    def test_loads_with_dates_and_controls(self, tmp_path):
        csv_text = ("finding_id,subject,title,severity,source,controls,detail,raised_on\n"
                    "F-1,v-1,Title,high,test,A.8.8;A.5.18,detail,2026-01-15\n")
        findings = ingest.load_findings(write(tmp_path, "f.csv", csv_text))
        assert findings[0].controls == ("A.8.8", "A.5.18")
        assert findings[0].raised_on.isoformat() == "2026-01-15"

    def test_blank_date_becomes_none(self, tmp_path):
        csv_text = ("finding_id,subject,title,severity,source,controls,detail,raised_on\n"
                    "F-1,v-1,Title,low,test,,,\n")
        assert ingest.load_findings(write(tmp_path, "f.csv", csv_text))[0].raised_on is None
