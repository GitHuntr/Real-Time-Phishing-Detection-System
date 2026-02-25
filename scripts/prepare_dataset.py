#!/usr/bin/env python3
"""
PhishGuard — Dataset Downloader Script
Downloads the UCI/Kaggle phishing URL dataset for training.
"""

import os
import urllib.request
import zipfile
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

DATASETS = {
    # Mendeley Phishing URL dataset (public)
    "phishing_urls": {
        "url": "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff",
        "filename": "uci_phishing.arff",
        "note": "UCI Phishing Websites Dataset",
    },
}


def create_sample_dataset():
    """Create a small sample CSV dataset for demonstration."""
    import csv

    sample_data = [
        # Phishing examples (label=1)
        ("http://paypa1-secure.verify-account.xyz/login?redirect=paypal.com", 1),
        ("http://192.168.1.1/bankofamerica/secure/login.php", 1),
        ("http://amazon-account-suspended.tk/verify", 1),
        ("http://bit.ly/3phishing-link", 1),
        ("http://appleid.apple.com.secure-verify.ml/signin", 1),
        ("http://www-paypal-com.paypal-secure.xyz/login", 1),
        ("http://microsoft365-update-required.online/secure", 1),
        ("http://secure-bankofamerica.ga/account/login", 1),
        ("https://xn--pple-43d.com/verify/account", 1),  # homograph
        ("http://login-facebook-verify.cf/checkpoint", 1),
        # Legitimate examples (label=0)
        ("https://www.google.com", 0),
        ("https://www.github.com/features", 0),
        ("https://stackoverflow.com/questions", 0),
        ("https://www.wikipedia.org/wiki/Python", 0),
        ("https://docs.python.org/3/library", 0),
        ("https://www.amazon.com/products", 0),
        ("https://mail.google.com/mail/u/0/", 0),
        ("https://www.linkedin.com/in/username", 0),
        ("https://www.microsoft.com/en-us/", 0),
        ("https://www.apple.com/iphone/", 0),
    ]

    csv_path = DATA_DIR / "sample_phishing_urls.csv"
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label'])
        writer.writerows(sample_data)

    print(f"Sample dataset created: {csv_path}")
    print(f"  {sum(1 for _, l in sample_data if l == 1)} phishing samples")
    print(f"  {sum(1 for _, l in sample_data if l == 0)} legitimate samples")
    print()
    print("NOTE: For production training, use a larger dataset:")
    print("  - Phishtank: https://phishtank.org/developer_info.php")
    print("  - UCI Phishing: https://archive.ics.uci.edu/dataset/327")
    print("  - Kaggle Web Page Phishing: https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset")
    return csv_path


if __name__ == '__main__':
    print("PhishGuard Dataset Setup")
    print("=" * 40)
    csv_path = create_sample_dataset()
    print()
    print(f"To train the model with this sample data:")
    print(f"  cd backend")
    print(f"  python model_trainer.py --data ../data/sample_phishing_urls.csv")
