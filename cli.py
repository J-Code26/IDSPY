import os
from ids_engine import AdaptiveIDSEngine, DEFAULT_MODEL


def print_banner():
    print("\n" + "=" * 65)
    print("  UNIVERSITY NETWORK IDS PROTOTYPE (CIS 321) - ADAPTIVE CLI")
    print("=" * 65)


def calc_metrics(stats):
    tp, fp, tn, fn = stats["tp"], stats["fp"], stats["tn"], stats["fn"]
    total_labeled = tp + fp + tn + fn
    if total_labeled == 0:
        return None
    accuracy = ((tp + tn) / total_labeled) * 100
    precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0
    fpr = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "f1": f1,
    }


def main():
    engine = AdaptiveIDSEngine()

    while True:
        print_banner()
        print(f"Model State: {engine.model['training_updates']} adaptive weight updates applied")
        print("-" * 65)
        print("1. Analyze CIC-IDS2017 CSV File (Score & Auto-Adapt)")
        print("2. Review 'Uncertain' Flagged Anomalies (Human-in-the-Loop)")
        print("3. View Alert Dashboard & Recent Detection History")
        print("4. Inspect Current ML Feature Weights & Bias")
        print("5. Reset Model Weights to Default Baseline")
        print("6. View Past Session Summaries ")
        print("7. Threat Evaluation and Analysis")
        print("8. Exit")
        print("-" * 65)

        choice = input("Select an option [1-8]: ").strip()

        if choice == "1":
            csv_path = input("Enter path to CIC-IDS2017 CSV file: ").strip().strip('"')
            limit_str = input("Max rows to process (press Enter for all): ").strip()
            limit = int(limit_str) if limit_str.isdigit() else None

            learn_ans = input("Enable real-time weight adaptation on errors? (Y/n): ").strip().lower()
            auto_learn = learn_ans != "n"

            try:
                print("\nProcessing traffic records and updating database...")
                stats = engine.process_csv(csv_path, auto_learn=auto_learn, limit=limit)
                print(f"\n--- ANALYSIS REPORT (RUN #{stats['run_number']}) ---")
                print(f"Records Analyzed   : {stats['total']}")
                print(f"Threats Detected   : {stats['threats']}")
                print(f"Benign Flows       : {stats['benign']}")
                print(f"Uncertain (Flagged): {stats['uncertain']}")
                print(f"Weight Adjustments : {stats['weight_adjustments']}")
                print(f"Records Analyzed   : {stats['total']} (in {stats['elapsed_seconds']}s)")

                metrics = calc_metrics(stats)
                if metrics:
                    print("\n--- EVALUATION METRICS ---")
                    print(f"Accuracy  : {metrics['accuracy']:.2f}% (Target: >= 85%)")
                    print(f"Recall    : {metrics['recall']:.2f}%")
                    print(f"Precision : {metrics['precision']:.2f}%")
                    print(f"F1-Score  : {metrics['f1']:.2f}%")
                    print(f"FPR       : {metrics['fpr']:.2f}% (Target: <= 15%)")
            except Exception as e:
                print(f"\n[ERROR] {e}")

            report_id, export_path = engine.save_and_export_report(csv_path, stats, metrics)
            print(f"\n[REPORT SAVED] Report #{report_id} logged to DB and exported to: {export_path}")

        elif choice == "2":
            uncertain = engine.get_uncertain_alerts(limit=10)
            if not uncertain:
                print("\nNo 'Uncertain' records awaiting human review.")
                continue

            print(f"\nFound {len(uncertain)} uncertain flows (40% - 69% probability):")
            for row in uncertain:
                aid, prob, port, dur, fwd, pkts_s, actual, _ = row
                print(
                    f"  ID #{aid} | Prob: {prob}% | DstPort: {port} | FwdPkts: {fwd} | "
                    f"Pkts/s: {pkts_s:.1f} | CSV Label: {actual}"
                )

            target_id = input("\nEnter Alert ID to classify (or Enter to go back): ").strip()
            if target_id.isdigit():
                verdict = input("Is this activity a THREAT? (y/n): ").strip().lower()
                if verdict in ("y", "n"):
                    success = engine.resolve_uncertain_alert(int(target_id), verdict == "y")
                    if success:
                        print(f"[OK] Alert #{target_id} updated and model weights adjusted for future detection.")
                    else:
                        print("[ERROR] Alert ID not found.")

        elif choice == "3":
            alerts = engine.get_recent_alerts(limit=15)
            if not alerts:
                print("\nNo detection records in database yet.")
                continue

            print("\n--- RECENT ALERT DASHBOARD ---")
            print(f"{'ID':<5} {'Class':<10} {'Prob%':<7} {'Port':<7} {'Pkts/s':<10} {'Actual':<12} {'Status'}")
            print("-" * 68)
            for a in alerts:
                aid, ts, cls, prob, port, pkts_s, bytes_s, actual, status = a
                print(
                    f"{aid:<5} {cls:<10} {prob:<7.1f} {port:<7} {pkts_s:<10.1f} {actual:<12} {status}"
                )

        elif choice == "4":
            print("\n--- CURRENT ADAPTIVE MODEL WEIGHTS ---")
            print(f"Bias          : {engine.model['bias']}")
            print(f"Learning Rate : {engine.model['learning_rate']}")
            print(f"Total Updates : {engine.model['training_updates']}")
            for feat, w in engine.model["weights"].items():
                print(f"  {feat:<24}: {w:+.5f}")

        elif choice == "5":
            engine._save_model(DEFAULT_MODEL.copy())
            print("\n[OK] Model weights reset to initial baseline.")

        elif choice == "6":
            reports = engine.get_past_reports(limit=10)
            if not reports:
                print("\nNo analysis reports saved yet. Run Option 1 first.")
                continue

            print("\n--- HISTORICAL ANALYSIS REPORTS ---")
            print(
                f"{'ID':<4} {'Date/Time':<20} {'File':<18} {'Rows':<7} {'Threats':<8} {'Acc%':<7} {'F1%':<7} {'FPR%'}")
            print("-" * 82)
            for r in reports:
                rid, ts, src, total, threats, unc, acc, f1, fpr = r
                short_src = (src[:15] + "...") if len(src) > 18 else src
                print(
                    f"{rid:<4} {ts:<20} {short_src:<18} {total:<7} {threats:<8} {acc:<7.1f} {f1:<7.1f} {fpr:.1f}"
                )

        elif choice == "7":
            target_id = input("\nEnter Alert ID to evaluate (use Option 3 to view IDs): ").strip()
            if not target_id.isdigit():
                print("[ERROR] Please enter a valid numeric Alert ID.")
                continue

            eval_data = engine.evaluate_alert(int(target_id))
            if not eval_data:
                print(f"[ERROR] Alert #{target_id} not found.")
                continue

            print("\n" + "=" * 65)
            print(f"  THREAT EVALUATION & ANALYST PLAYBOOK (ALERT #{eval_data['alert_id']})")
            print("=" * 65)
            print(f"Classification : {eval_data['classification']} ({eval_data['probability']}%)")
            print(f"Severity Tier  : {eval_data['severity']}")
            print(f"Likely Vector  : {eval_data['profile']}")
            print(f"Current Status : {eval_data['status']} | Action Logged: {eval_data['action_taken']}")

            print("\n--- FLOW TELEMETRY ---")
            for k, v in eval_data["raw_metrics"].items():
                print(f"  {k:<20}: {v}")

            print("\n--- TOP ML RISK DRIVERS (WEIGHT x NORMALIZED INPUT) ---")
            for feat, score in eval_data["top_drivers"]:
                print(f"  {feat:<24}: {score:+.4f}")

            print("\n--- RECOMMENDED ANALYST NEXT ACTIONS ---")
            for idx, act in enumerate(eval_data["recommended_actions"], start=1):
                print(f"  {idx}. {act}")
            print("=" * 65)

            log_choice = input("\nLog a taken action [1-3], type custom note, or Enter to skip: ").strip()
            if log_choice in ("1", "2", "3") and int(log_choice) <= len(eval_data["recommended_actions"]):
                chosen_action = eval_data["recommended_actions"][int(log_choice) - 1]
                engine.log_analyst_action(eval_data["alert_id"], chosen_action)
                print(f"[OK] Logged action: '{chosen_action}'")
            elif log_choice:
                engine.log_analyst_action(eval_data["alert_id"], log_choice)
                print(f"[OK] Logged custom action: '{log_choice}'")

        elif choice == "8":
            print("Exiting University IDS CLI.")
            break


if __name__ == "__main__":
    main()