import gzip
import json
import tempfile
import unittest
from pathlib import Path

from ru_blacklist.inetnum import parse


class ParseRipeDbTests(unittest.TestCase):
    def test_skips_non_ru_last_record_and_normalizes_last_ru_record(self):
        sample = """\
inetnum: 10.0.0.0 - 10.0.0.255
netname: TEST1
country: RU
org: ORG-1
descr: desc1
inetnum: 20.0.0.0 - 20.0.0.255
netname: TEST2
country: US
org: ORG-2
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "ripe.db.inetnum"
            output_text = Path(tmpdir) / "out.txt"
            output_json = Path(tmpdir) / "out.json"
            source.write_text(sample, encoding="latin-1")

            parse(str(source), str(output_text), str(output_json))

            payload = json.loads(output_json.read_text(encoding="utf-8"))
            self.assertEqual(len(payload), 1)
            self.assertEqual(payload[0]["inetnum"], ["10.0.0.0/24"])
            self.assertEqual(payload[0]["country"], "RU")

            text_lines = output_text.read_text(encoding="utf-8").splitlines()
            self.assertEqual(text_lines, ["10.0.0.0/24 TEST1 (ORG-1) [desc1]"])

    def test_reads_gzip_skips_malformed_and_accepts_lowercase_country(self):
        sample = """\
inetnum: 10.0.0.0 - 10.0.1.255
netname: TEST1
mnt-by: VKCOMPANY-MNT
country: ru

inetnum: broken
netname: BAD
country: RU
"""

        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "ripe.db.inetnum.gz"
            output_text = Path(tmpdir) / "out.txt"
            output_json = Path(tmpdir) / "out.json"
            with gzip.open(source, "wt", encoding="latin-1") as dump:
                dump.write(sample)

            parse(str(source), str(output_text), str(output_json))

            text_lines = output_text.read_text(encoding="utf-8").splitlines()
            self.assertEqual(text_lines, ["10.0.0.0/23 TEST1 VKCOMPANY-MNT () []"])

    def test_no_matching_records_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "ripe.db.inetnum"
            source.write_text("inetnum: 10.0.0.0 - 10.0.0.255\ncountry: US\n", encoding="latin-1")

            with self.assertRaises(ValueError):
                parse(str(source), str(Path(tmpdir) / "o.txt"), str(Path(tmpdir) / "o.json"))


if __name__ == "__main__":
    unittest.main()
