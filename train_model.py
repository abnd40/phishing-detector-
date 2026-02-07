#!/usr/bin/env python3
"""
Model Training Script for Phishing Email Detector
=================================================
Trains an ML model on labeled email data for phishing classification.

This script can:
1. Load emails from directories (phishing/ and legitimate/)
2. Generate synthetic training data for demonstration
3. Train and evaluate a Random Forest classifier
4. Save the trained model for use with the detector
"""

import os
import random
from pathlib import Path
from typing import List, Tuple
import json

import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import joblib

from phishing_detector import PhishingModelTrainer, PhishingDetector


# Synthetic training data for demonstration purposes
PHISHING_TEMPLATES = [
    # Urgency + credential theft
    """Subject: URGENT: Your account has been compromised!

    Dear Customer,

    We have detected unusual activity on your account. Your access has been
    temporarily suspended. You must verify your identity within 24 hours or
    your account will be permanently closed.

    Click here to verify: http://secure-verify.tk/login

    You will need to provide your password, social security number, and
    credit card details for verification.

    Act now to prevent account termination!

    Security Team""",

    # Prize scam
    """Subject: Congratulations! You've Won $1,000,000!!!

    CONGRATULATIONS!!!

    You have been selected as our lucky winner! You've won ONE MILLION DOLLARS
    in our exclusive lottery program!!

    To claim your prize immediately, click below:
    http://claim-prize-now.ml/winner

    Provide your bank account number and routing number for direct deposit.

    HURRY! This offer expires in 48 hours!

    Don't miss this once in a lifetime opportunity!!!""",

    # Fake invoice
    """Subject: Invoice #INV-98234 - Payment Required Immediately

    Dear Valued Customer,

    Please find attached invoice for $4,582.00 due immediately.

    Failure to pay within 12 hours will result in legal action and additional fees.

    Download invoice: http://192.168.1.1/invoice.exe

    To make payment, provide:
    - Full name
    - Bank account details
    - Credit card number

    This is your final warning.

    Accounts Receivable""",

    # Password reset scam
    """Subject: Your password expires today - Update now!

    Your password will expire in 2 hours. You must update it immediately or
    lose access to your account.

    Click here to keep your current password: http://bit.ly/pwd-update

    Enter your current password and new password on the secure form.

    This is an automated message. Failure to respond will lock your account.

    IT Security Team""",

    # Fake delivery
    """Subject: Package delivery failed - Verify address now!

    We attempted to deliver your package but failed. Your package is being
    held at our facility.

    Verify your address within 24 hours or the package will be returned:
    http://fedx-delivery.xyz/verify

    A $3.99 redelivery fee will be charged to your credit card on file.

    Provide updated shipping address and payment information.

    FedEx Delivery Services""",

    # Tech support scam
    """Subject: ALERT: Virus detected on your computer!

    CRITICAL SECURITY ALERT!!!

    We have detected a dangerous virus on your computer. Your files are at risk!

    Call immediately: 1-800-FAKE-NUM
    Or click: http://microsoft-support.ga/fix

    Our certified technicians will remove the virus. Payment required.

    Microsoft Technical Support
    Do the needful immediately.""",

    # Bank alert
    """Subject: Suspicious transaction detected - Verify now

    Dear Customer,

    We has detected unauthorized transaction on your account:
    Amount: $2,500.00
    Location: Lagos, Nigeria

    If this wasn't you, click immediately to secure your account:
    http://chase-secure.pw/verify

    Provide your account number, PIN, and social security number.

    Failure to verify will result in account suspension.

    Chase Bank Security""",

    # Gift card scam
    """Subject: Get your free $500 Amazon gift card!!!

    YOU'VE BEEN SELECTED!!!

    Complete a short survey and receive a FREE $500 Amazon gift card!

    CLICK NOW: http://amaz0n-rewards.tk/survey

    Limited time offer! Only 100 gift cards remaining!!!

    Enter your email, password, and credit card for shipping fee ($1.99).

    ACT FAST before they're gone!!!!""",

    # Account verification
    """Subject: Verify your account to avoid suspension

    Dear User,

    We need you to confirm your account information. Unverified accounts
    will be terminated within 24 hours.

    Click to verify: http://login-verify.cf/confirm

    Required information:
    - Username and password
    - Date of birth
    - Mother's maiden name
    - Last 4 digits of SSN

    Thank you for your cooperation.

    Account Security Team""",

    # Fake refund
    """Subject: Your refund of $847.50 is pending

    A refund of $847.50 has been issued to your account. However, we need
    additional verification before processing.

    Click here to claim your refund: http://refund-process.work/claim

    You must verify your bank account and routing number within 48 hours
    or the refund will be cancelled.

    Kindly do the needful.

    Customer Refunds Department""",
]

LEGITIMATE_TEMPLATES = [
    # GitHub notification
    """Subject: [username/repo] Pull request merged: Fix memory leak (#234)

    The pull request #234 has been merged into main.

    Fix memory leak in cache module

    This PR addresses the memory leak reported in issue #230. The cache
    was not properly releasing references when items expired.

    View on GitHub: https://github.com/username/repo/pull/234

    You are receiving this because you are subscribed to this repository.""",

    # Company newsletter
    """Subject: Weekly Update: Q1 Results and Upcoming Town Hall

    Hello Team,

    Here are the key updates for this week:

    Q1 Financial Results
    We are pleased to announce that Q1 results exceeded expectations with
    revenue growth of 12% year-over-year.

    Upcoming Town Hall
    Join us on Friday at 2:00 PM for the quarterly meeting.

    Best regards,
    The Communications Team""",

    # Order confirmation
    """Subject: Your order has shipped - Tracking #1Z999AA10123456784

    Hello,

    Great news! Your order has shipped and is on its way.

    Order Details:
    - Wireless Bluetooth Headphones
    - Quantity: 1
    - Price: $49.99

    Track your package: https://www.amazon.com/track/1Z999AA10123456784

    Estimated delivery: Thursday, March 21

    Thank you for shopping with us.""",

    # Calendar invite
    """Subject: Meeting Invitation: Product Review - March 25, 10:00 AM

    You have been invited to a meeting.

    Product Review Meeting
    When: March 25, 2024, 10:00 AM - 11:00 AM EST
    Where: Conference Room B / Microsoft Teams

    Agenda:
    1. Q1 product metrics review
    2. Roadmap discussion for Q2
    3. Customer feedback analysis

    Please confirm your attendance.

    Best,
    Product Team""",

    # Receipt
    """Subject: Receipt for your payment to Netflix

    Hello,

    You sent a payment of $15.99 to Netflix.

    Transaction ID: 8AB12345CD678901E
    Date: March 20, 2024
    Payment method: Visa ending in 4242

    Monthly subscription renewal.

    View transaction: https://www.paypal.com/activity/payment/8AB12345CD678901E

    Thanks for using PayPal.""",

    # LinkedIn connection
    """Subject: John Smith accepted your invitation to connect

    Hi there,

    John Smith has accepted your invitation. You're now connected!

    John Smith
    Software Engineer at Tech Company
    San Francisco Bay Area

    Start a conversation with John.

    View profile: https://www.linkedin.com/in/johnsmith

    LinkedIn Corporation""",

    # Software update
    """Subject: Visual Studio Code - March 2024 Update (version 1.88)

    Visual Studio Code version 1.88 is now available.

    New Features:
    - Improved Python debugging
    - Enhanced Git integration
    - New color themes

    Read the release notes: https://code.visualstudio.com/updates/v1_88

    Update now through the application or download from our website.

    The VS Code Team""",

    # Customer support
    """Subject: Re: Support Ticket #45678 - Issue Resolved

    Hello,

    Thank you for contacting our support team. We have resolved the issue
    you reported regarding your account settings.

    The configuration has been updated and you should now be able to
    access all features normally.

    If you have any further questions, please reply to this email.

    Best regards,
    Sarah
    Customer Support Team""",

    # Newsletter subscription
    """Subject: Welcome to our newsletter!

    Thanks for subscribing!

    You'll receive our weekly digest with:
    - Industry news and insights
    - Tips and tutorials
    - Product updates

    Manage your preferences: https://example.com/preferences
    Unsubscribe: https://example.com/unsubscribe

    Welcome aboard!""",

    # Service notification
    """Subject: Scheduled Maintenance - March 23, 2:00 AM EST

    Hello,

    We will be performing scheduled maintenance on our systems:

    Date: Saturday, March 23, 2024
    Time: 2:00 AM - 6:00 AM EST

    During this time, the service may be temporarily unavailable.

    We apologize for any inconvenience.

    Infrastructure Team""",
]


def generate_training_data(
    n_samples: int = 500,
    phishing_ratio: float = 0.5
) -> Tuple[List[str], List[int]]:
    """
    Generate synthetic training data by sampling and varying templates.

    Args:
        n_samples: Total number of samples to generate
        phishing_ratio: Proportion of phishing samples

    Returns:
        Tuple of (texts, labels) where label 1 = phishing, 0 = legitimate
    """
    texts = []
    labels = []

    n_phishing = int(n_samples * phishing_ratio)
    n_legitimate = n_samples - n_phishing

    # Generate phishing samples
    for _ in range(n_phishing):
        template = random.choice(PHISHING_TEMPLATES)
        # Add some variation
        text = _add_variation(template, is_phishing=True)
        texts.append(text)
        labels.append(1)

    # Generate legitimate samples
    for _ in range(n_legitimate):
        template = random.choice(LEGITIMATE_TEMPLATES)
        text = _add_variation(template, is_phishing=False)
        texts.append(text)
        labels.append(0)

    # Shuffle
    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)

    return list(texts), list(labels)


def _add_variation(text: str, is_phishing: bool) -> str:
    """Add random variations to text for diversity."""
    variations = text

    if is_phishing:
        # Add urgency variations
        urgency_words = ['URGENT', 'IMMEDIATE', 'ACTION REQUIRED', 'ALERT']
        if random.random() > 0.5:
            variations = random.choice(urgency_words) + ': ' + variations

        # Add exclamation marks
        if random.random() > 0.7:
            variations = variations.replace('!', '!!!')
    else:
        # Vary greetings for legitimate
        greetings = ['Hello', 'Hi', 'Dear User', 'Greetings']
        for greeting in ['Hello', 'Hi', 'Dear']:
            if greeting in variations and random.random() > 0.5:
                variations = variations.replace(greeting, random.choice(greetings), 1)
                break

    return variations


def load_sample_emails(samples_dir: str) -> Tuple[List[str], List[int]]:
    """Load sample emails from the samples directory."""
    texts = []
    labels = []

    samples_path = Path(samples_dir)

    # Load phishing samples
    phishing_dir = samples_path / 'phishing'
    if phishing_dir.exists():
        for eml_file in phishing_dir.glob('*.eml'):
            try:
                detector = PhishingDetector()
                msg = detector._parse_email(str(eml_file), is_file=True)
                subject = msg.get('Subject', '')
                body_text, body_html = detector._extract_body(msg)
                body = body_text or detector._html_to_text(body_html)
                texts.append(f"{subject}\n{body}")
                labels.append(1)
            except Exception as e:
                print(f"Error loading {eml_file}: {e}")

    # Load legitimate samples
    legit_dir = samples_path / 'legitimate'
    if legit_dir.exists():
        for eml_file in legit_dir.glob('*.eml'):
            try:
                detector = PhishingDetector()
                msg = detector._parse_email(str(eml_file), is_file=True)
                subject = msg.get('Subject', '')
                body_text, body_html = detector._extract_body(msg)
                body = body_text or detector._html_to_text(body_html)
                texts.append(f"{subject}\n{body}")
                labels.append(0)
            except Exception as e:
                print(f"Error loading {eml_file}: {e}")

    return texts, labels


def train_and_evaluate(
    texts: List[str],
    labels: List[int],
    output_path: str = 'models/phishing_model.joblib'
) -> dict:
    """
    Train model and evaluate performance.

    Args:
        texts: List of email texts
        labels: List of labels (0 or 1)
        output_path: Path to save the trained model

    Returns:
        Dictionary of evaluation metrics
    """
    print(f"\nTraining on {len(texts)} samples...")
    print(f"  Phishing: {sum(labels)}")
    print(f"  Legitimate: {len(labels) - sum(labels)}")

    trainer = PhishingModelTrainer()

    # Train with evaluation
    metrics = trainer.train(texts, labels, test_size=0.2)

    print("\n" + "=" * 50)
    print("TRAINING RESULTS")
    print("=" * 50)
    print(f"Training samples: {metrics['train_samples']}")
    print(f"Test samples: {metrics['test_samples']}")
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.2%}")
    print(f"  Precision: {metrics['precision']:.2%}")
    print(f"  Recall:    {metrics['recall']:.2%}")
    print(f"  F1 Score:  {metrics['f1']:.2%}")

    # Cross-validation
    print("\nPerforming 5-fold cross-validation...")
    X_vec = trainer.vectorizer.fit_transform(texts)
    cv_scores = cross_val_score(trainer.model, X_vec, labels, cv=5, scoring='f1')
    print(f"Cross-validation F1: {cv_scores.mean():.2%} (+/- {cv_scores.std()*2:.2%})")

    # Save model
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    trainer.save(output_path)
    print(f"\nModel saved to: {output_path}")

    return metrics


def main():
    """Main training workflow."""
    import argparse

    parser = argparse.ArgumentParser(description='Train phishing detection model')
    parser.add_argument('--samples', '-s', type=str, default='samples',
                        help='Directory containing sample emails')
    parser.add_argument('--output', '-o', type=str, default='models/phishing_model.joblib',
                        help='Output path for trained model')
    parser.add_argument('--synthetic', '-n', type=int, default=500,
                        help='Number of synthetic samples to generate')
    parser.add_argument('--no-synthetic', action='store_true',
                        help='Only use real samples, no synthetic data')

    args = parser.parse_args()

    print("=" * 50)
    print("PHISHING EMAIL DETECTOR - MODEL TRAINING")
    print("=" * 50)

    all_texts = []
    all_labels = []

    # Load real samples
    print("\nLoading sample emails...")
    sample_texts, sample_labels = load_sample_emails(args.samples)
    print(f"  Loaded {len(sample_texts)} sample emails")
    all_texts.extend(sample_texts)
    all_labels.extend(sample_labels)

    # Generate synthetic data
    if not args.no_synthetic:
        print(f"\nGenerating {args.synthetic} synthetic samples...")
        synth_texts, synth_labels = generate_training_data(args.synthetic)
        all_texts.extend(synth_texts)
        all_labels.extend(synth_labels)

    if len(all_texts) < 10:
        print("\nError: Not enough training data. Need at least 10 samples.")
        return

    # Train and evaluate
    metrics = train_and_evaluate(all_texts, all_labels, args.output)

    # Save metrics
    metrics_path = args.output.replace('.joblib', '_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to: {metrics_path}")

    print("\n" + "=" * 50)
    print("TRAINING COMPLETE")
    print("=" * 50)


if __name__ == '__main__':
    main()
