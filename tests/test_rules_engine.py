from ace_t_osint.detectors.rules_engine import RulesEngine
from ace_t_osint.detectors.analyzer import Detector
from ace_t_osint.detectors.entities_loader import EntityLoader
from ace_t_osint.utils.sentiment import SentimentAnalyzer


def test_rules_engine_matches_triggers(tmp_path):
    engine = RulesEngine("ace_t_osint/triggers/triggers.json")
    entities = EntityLoader("ace_t_osint/entities").load()
    sentiment = SentimentAnalyzer("ace_t_osint/entities/sentiment_lexicon.txt")
    detector = Detector(engine, entities, sentiment)

    text = "Password leak exploit referencing CVE-2024-12345"
    matches = list(detector.detect(text))
    assert matches
    assert matches[0].sentiment in {"neg", "neu", "pos"}
