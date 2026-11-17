# Intrusion Detection System for Educational Institutions or General IT

## Project Description

**IDSPY (Network IDS for Universities)** is a lightweight, terminal-based Network Intrusion Detection System prototype developed for CIS 321 by Jayden McFadden, Julius Carter, and Gavin Carroll. Designed with the resource constraints and diverse traffic profiles of university networks in mind, the system analyzes bidirectional network flow records from the **CIC-IDS2017** dataset using a continuous `0–100%` threat probability scoring engine.

Unlike rigid, static firewall rules, IDSPY incorporates an **online adaptive learning loop** (Stochastic Gradient Descent) backed by a normalized SQLite database (`university_ids.db`) and persistent JSON model weights (`model_weights.json`). When the engine encounters misclassified traffic or ambiguous activity within its `40–69%` uncertainty band, it flags the flow for human-in-the-loop analyst review, recommends targeted campus containment actions, and dynamically updates its feature weights to improve future detection accuracy while minimizing false alerts.

### Key Features
* **6-Feature Flow Ingestion & Cleaning:** Automatically parses and normalizes core CIC-IDS2017 telemetry (`Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Flow Packets/s`, and `Flow Bytes/s`).
* **Continuous Threat Probability Scoring:** Evaluates network flows on a `0–100%` scale, categorizing traffic into **Confirmed Threats (`≥70%`)**, **Uncertain / Needs Review (`40–69%`)**, and **Benign (`<40%`)**.
* **Self-Adjusting ML Weights:** Updates feature weights and bias automatically when errors occur during calibration or when a security analyst resolves an uncertain flag.
* **Analyst Triage & Response Playbook:** Identifies the top ML risk drivers behind any alert and provides tailored campus IT containment steps with audit logging.
* **Automated Reporting & Metrics:** Tracks Accuracy, Recall, Precision, F1-Score, and False Positive Rate (FPR) across sessions in SQLite and exports formatted `.txt` summary reports.

## Instructions for running

### This section is for after you have already pulled the repository. 

First, go to https://www.unb.ca/cic/datasets/ids-2017.html to download the database from CICIDS2017 record. 

1. Once you have the ZIP file that is the Machine learning container, select the Port scan CSV, or any other that you are planning on testing. 

2. When you have that file, put it in a place where you know the directory, since that will be used to gain access to the information to be analyzed. 

3. Run the cli.py file either within an IDE or on your terminal by using cd <where ever your project folder is> and within that directory, run python3 with the cli.py file to begin.

4. The program will automatically keep track of analysis through a log, while also creating an exported text file of each completed analysis. 
