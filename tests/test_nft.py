import unittest

from ru_blacklist.nft import detect_family, main, make_nft_config


class GenerateNftBlacklistTests(unittest.TestCase):
    def test_generates_plain_sets_only(self):
        config = make_nft_config(["10.0.0.0/24"], [])

        self.assertIn("set blacklist_v4", config)
        self.assertNotIn("chain input", config)
        self.assertIn("ip saddr @blacklist_v4", config)

    def test_sets_are_flushed_before_refill(self):
        config = make_nft_config(["10.0.0.0/24"], ["2001:db8::/32"])

        declare = config.index("set blacklist_v4 {")
        flush = config.index("flush set inet filter blacklist_v4")
        fill = config.index("10.0.0.0/24")
        self.assertLess(declare, flush)
        self.assertLess(flush, fill)

    def test_single_family_file_only_touches_its_own_set(self):
        config = make_nft_config(["10.0.0.0/24"], [], family="4")

        self.assertIn("set blacklist_v4", config)
        self.assertNotIn("blacklist_v6", config)

    def test_family_detection(self):
        self.assertEqual(detect_family("output/txt/blacklist-v4.txt"), "4")
        self.assertEqual(detect_family("blacklist-v6.txt"), "6")
        self.assertEqual(detect_family("blacklist.txt"), "both")

    def test_cli_aggregates_and_names_source_without_path(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "blacklist-v4.txt"
            source.write_text("10.0.0.0/25\n10.0.0.128/25\n2001:db8::/32\n", encoding="utf-8")
            output = Path(tmpdir) / "out.nft"

            self.assertEqual(main(["--quiet", str(source), str(output)]), 0)
            config = output.read_text(encoding="utf-8")

        self.assertIn("# Source: blacklist-v4.txt", config)
        self.assertIn("10.0.0.0/24", config)
        self.assertNotIn("2001:db8::/32", config)
        self.assertNotIn(tmpdir, config)


if __name__ == "__main__":
    unittest.main()
