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

## Detailed instructions

1. Read previous instructions if needed. 
2. Review the README information to understand how the program works.
3. You can clone the repository through an IDE or terminal, open the project folder, and run the cli.py file (using python3 cli.py), which is the main interface script—no external package installations are required.
4. Once that is run, the main terminal menu will pop up.
5. Now that the program is set up, follow the dataset link in the README (the CIC-IDS2017 dataset from the Canadian Institute for Cybersecurity) and download it to your personal or work computer; you may have to enter your email and occupation on their site to access the download.   
6. Extract the files and make sure to locate the PortScan CSV (and optionally the DDoS CSV for unseen testing).   
7. Once everything is downloaded, navigate to the CSV file on your computer and copy its full file path.
8. Go back to the terminal where the script is running and continue with the prompts.
9. Select Option 1 to run the initial analysis. Choose your preferred row limit and learning settings, and when it asks for the path to the CSV, paste the copied path (without extra quotes if needed).
10. The live progress counter will track the rows and notify you when it is finished, and you can then view the summary on screen or navigate to the other menu options to inspect specific alerts, review uncertain flags, and see past sessions and reports.
11. Lastly, you can exit at any time, and for each completed run, you can review the exported .txt version inside the reports/ folder within the project directory.
