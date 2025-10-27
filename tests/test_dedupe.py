from ace_t_osint.utils.hashing import hamming_distance, sha256_hash, simhash


def test_simhash_similarity():
    text_a = "password leak credential"
    text_b = "password leak credential exposed"
    hash_a = simhash(text_a)
    hash_b = simhash(text_b)
    assert hamming_distance(hash_a, hash_b) < 16


def test_sha256_consistency():
    text = "  password   leak  "
    assert sha256_hash(text) == sha256_hash("password leak")
