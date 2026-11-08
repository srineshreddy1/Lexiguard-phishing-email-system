import itertools
import pytest
from lexiguard.parser import parse_url
from lexiguard.features import extract_features


def generate_fuzz_matrix() -> list[str]:
    """Generates a combinatorial matrix of over 1,000 unique URL permutations."""
    schemes = ["http://", "https://", "//", ""]
    credentials = ["", "user:pass@", "admin%40evil@"]
    hosts = [
        "example.com",
        "EXAMPLE.COM",
        "sub.domain.example.com",
        "a.b.c.d.e.k8x9z2m4q1w7v5j3p6h4.com",
        "xn--bcher-kva.example",
        "münchen.example",
        "127.0.0.1",
        "0x7f000001",
        "2130706433",
        "0177.0.0.1",
        "[2001:db8::8]",
        r"legitimate.com\evil.com",
    ]
    ports = ["", ":80", ":8080", ":9999"]
    paths = [
        "",
        "/",
        "/login",
        "/secure/verify-account",
        "/../../etc/passwd",
        r"/path\with\backslashes",
    ]
    queries = ["", "?update=1&signin=true", "?q=%2Flogin", "?banking=true"]

    # Cartesian product generates thousands of rigorous permutations
    matrix = list(
        itertools.product(schemes, credentials, hosts, ports, paths, queries)
    )
    
    urls = []
    for s, c, h, p, pt, q in matrix:
        url = f"{s}{c}{h}{p}{pt}{q}"
        if len(url) <= 2048:  # Respect max length boundary
            urls.append(url)
            
    return urls


def test_phase_1_parser_fuzz_mass() -> None:
    """Isolate Phase 1: Tests 1,000+ inputs for unhandled exceptions or crashes."""
    urls = generate_fuzz_matrix()
    assert len(urls) >= 1000, f"Generated only {len(urls)} URLs, expected >= 1000"

    for url in urls:
        result = parse_url(url)
        assert isinstance(result, dict)
        assert "raw" in result
        assert "warnings" in result


def test_phase_2_features_fuzz_mass() -> None:
    """Isolate Phase 2: Tests feature extraction and policy enforcement on 1,000+ parse outputs without crashing."""
    urls = generate_fuzz_matrix()

    for url in urls:
        parsed = parse_url(url)
        feature_result = extract_features(parsed)
        
        assert isinstance(feature_result, dict)
        assert "features" in feature_result
        assert "policy_violations" in feature_result
        
        # Verify feature shape integrity
        features = feature_result["features"]
        assert isinstance(features["hostname_length"], int)
        assert isinstance(features["hostname_entropy"], float)
        assert isinstance(feature_result["policy_violations"], list)


def test_isolated_non_dict_and_malformed_phase_2() -> None:
    """Tests Phase 2 resilience against completely malformed phase 1 inputs."""
    bad_inputs = [None, "not-a-dict", 12345, {"incomplete": True}, []]
    for bad in bad_inputs:
        result = extract_features(bad)  # type: ignore[arg-type]
        assert isinstance(result, dict)
        assert "policy_violations" in result