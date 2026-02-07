#!/usr/bin/env python3
"""
Phishing Email Detector - Demo Script
=====================================
Demonstrates the detection capabilities on sample emails.

Run: python demo.py
"""

from pathlib import Path
from phishing_detector import PhishingDetector, ReportGenerator


def run_demo():
    """Run demonstration on all sample emails."""
    print("=" * 70)
    print("PHISHING EMAIL DETECTOR - DEMONSTRATION")
    print("=" * 70)
    print()

    detector = PhishingDetector()
    reporter = ReportGenerator()

    samples_dir = Path(__file__).parent / 'samples'

    # Process phishing samples
    print("ANALYZING PHISHING SAMPLES")
    print("-" * 70)
    phishing_dir = samples_dir / 'phishing'
    if phishing_dir.exists():
        for eml_file in sorted(phishing_dir.glob('*.eml')):
            try:
                result = detector.analyze_email(str(eml_file), is_file=True)
                verdict = "PHISHING" if result.is_phishing else "LEGITIMATE"
                icon = "[!]" if result.is_phishing else "[OK]"
                print(f"{icon} {eml_file.name}")
                print(f"    Verdict: {verdict}")
                print(f"    Risk Level: {result.risk_level}")
                print(f"    Risk Score: {result.risk_score:.2%}")
                if result.top_indicators[:3]:
                    print("    Top Indicators:")
                    for ind in result.top_indicators[:3]:
                        print(f"      - {ind}")
                print()
            except Exception as e:
                print(f"[ERROR] {eml_file.name}: {e}")
                print()

    # Process legitimate samples
    print("ANALYZING LEGITIMATE SAMPLES")
    print("-" * 70)
    legit_dir = samples_dir / 'legitimate'
    if legit_dir.exists():
        for eml_file in sorted(legit_dir.glob('*.eml')):
            try:
                result = detector.analyze_email(str(eml_file), is_file=True)
                verdict = "PHISHING" if result.is_phishing else "LEGITIMATE"
                icon = "[!]" if result.is_phishing else "[OK]"
                print(f"{icon} {eml_file.name}")
                print(f"    Verdict: {verdict}")
                print(f"    Risk Level: {result.risk_level}")
                print(f"    Risk Score: {result.risk_score:.2%}")
                if result.top_indicators[:2]:
                    print("    Indicators:")
                    for ind in result.top_indicators[:2]:
                        print(f"      - {ind}")
                print()
            except Exception as e:
                print(f"[ERROR] {eml_file.name}: {e}")
                print()

    # Full report for one phishing email
    print("=" * 70)
    print("DETAILED REPORT EXAMPLE")
    print("=" * 70)
    print()

    sample_phishing = samples_dir / 'phishing' / 'paypal_urgent.eml'
    if sample_phishing.exists():
        result = detector.analyze_email(str(sample_phishing), is_file=True)
        print(reporter.generate_text_report(result))

    print()
    print("=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print()
    print("Usage:")
    print("  python phishing_detector.py <email.eml>        # Analyze a file")
    print("  python phishing_detector.py --text '<email>'   # Analyze raw text")
    print("  python phishing_detector.py samples/ --batch   # Batch analyze")
    print("  python train_model.py                          # Train ML model")


if __name__ == '__main__':
    run_demo()
