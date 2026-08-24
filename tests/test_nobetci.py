"""Offline tests — no network, no API key. Run with:  python -m unittest discover -s tests"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nobetci import extract, heuristics, store  # noqa: E402
from nobetci.classify import HeuristicClassifier, _parse  # noqa: E402


class TestNormalise(unittest.TestCase):
    def test_turkish_dotless_i_folds_to_ascii(self):
        # The whole term list depends on this: "BAHİS", "bahis" and "bahıs"
        # must all reach the same entry.
        self.assertEqual(heuristics.normalise("BAHİS"), "bahis")
        self.assertEqual(heuristics.normalise("bahıs"), "bahis")
        self.assertEqual(heuristics.normalise("Güvenilir"), "guvenilir")


class TestScan(unittest.TestCase):
    def test_gambling_spam_is_a_strong_signal(self):
        signals = heuristics.scan("Güvenilir bahis siteleri ve canlı bahis, deneme bonusu veren siteler")
        best = heuristics.strongest(signals)
        self.assertIsNotNone(best)
        self.assertEqual(best.category, "gambling")
        self.assertTrue(best.strong)

    def test_clean_business_copy_produces_nothing(self):
        signals = heuristics.scan("Ankara'da 20 yıldır inşaat ve taahhüt hizmeti veriyoruz.")
        self.assertEqual(signals, [])

    def test_single_mention_is_not_strong(self):
        # A law firm writing about gambling regulation must not be flagged.
        signals = heuristics.scan("Kumar hukuku alanında danışmanlık veriyoruz.")
        best = heuristics.strongest(signals)
        self.assertIsNotNone(best)
        self.assertFalse(best.strong)


class TestClassifier(unittest.TestCase):
    def setUp(self):
        self.c = HeuristicClassifier()

    def test_obvious_spam_is_hostile(self):
        v = self.c.classify(business="inşaat", url="x", text="canlı bahis deneme bonusu casino rulet")
        self.assertTrue(v.hostile)
        self.assertEqual(v.source, "heuristic")

    def test_single_term_is_unclear_not_hostile(self):
        v = self.c.classify(business="hukuk", url="x", text="kumar hukuku hakkında")
        self.assertEqual(v.label, "unclear")

    def test_clean_text_is_benign(self):
        v = self.c.classify(business="inşaat", url="x", text="Projelerimiz ve referanslarımız")
        self.assertEqual(v.label, "benign")


class TestParse(unittest.TestCase):
    def test_plain_json(self):
        v = _parse('{"label": "hostile", "confidence": 0.9, "reason": "casino"}')
        self.assertTrue(v.hostile)

    def test_fenced_json_still_parses(self):
        v = _parse('```json\n{"label": "benign", "confidence": 0.8, "reason": "ok"}\n```')
        self.assertEqual(v.label, "benign")

    def test_garbage_degrades_to_unclear(self):
        self.assertEqual(_parse("I'm not sure about this").label, "unclear")

    def test_unknown_label_degrades_to_unclear(self):
        self.assertEqual(_parse('{"label": "spicy", "confidence": 1}').label, "unclear")


class TestExtract(unittest.TestCase):
    def test_script_and_style_are_not_page_text(self):
        page = extract.Page("https://x.test/", """
            <html><head><title> Ana Sayfa </title><style>.a{color:red}</style></head>
            <body><script>var bahis = 1;</script><p>İnşaat firması</p></body></html>""")
        self.assertEqual(page.title, "Ana Sayfa")
        self.assertIn("İnşaat firması", page.text)
        self.assertNotIn("bahis", page.text)  # a JS variable is not page content

    def test_internal_links_only(self):
        page = extract.Page("https://x.test/", """
            <a href="/a">a</a><a href="https://other.test/b">b</a>
            <a href="mailto:x@y.z">m</a><a href="/a/">dup</a>""")
        self.assertEqual(page.internal_links(), ["https://x.test/a"])

    def test_robots_sitemaps(self):
        found = extract.robots_sitemaps("User-agent: *\nSitemap: https://x.test/sitemap.xml\nsitemap: https://x.test/sitemap-2.xml")
        self.assertEqual(len(found), 2)


class TestStore(unittest.TestCase):
    def test_added_returns_only_new(self):
        self.assertEqual(store.added(["a", "b"], ["b", "c"]), ["c"])

    def test_roundtrip_and_baseline_flag(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            snap = store.Snapshot.load(directory, "https://x.test")
            self.assertFalse(snap.seen)  # unseen site must start as a baseline
            snap.pages = ["https://x.test/a"]
            snap.seen = True
            snap.save(directory)
            again = store.Snapshot.load(directory, "https://x.test")
            self.assertTrue(again.seen)
            self.assertEqual(again.pages, ["https://x.test/a"])


if __name__ == "__main__":
    unittest.main()
