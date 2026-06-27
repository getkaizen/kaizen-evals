#!/usr/bin/env python3
"""Aggregate every benchmark's results/*.json into one source of truth: results/results.json.
The PDF, docs page, homepage stat, and GitHub all read from this. No hand-typed numbers."""
import os, json, glob

HERE = os.path.dirname(__file__)
RESULTS = os.path.join(HERE, "results")

ORDER = ["egress_bench", "injecagent", "agentdojo", "asb", "cyberseceval", "memory_integrity"]
META = {
    "egress_bench": {"name": "agent-egress-bench", "kind": "external", "what": "197-case egress-security corpus that tests the security tool, not the model", "owasp": ["LLM02 Sensitive Information Disclosure", "LLM01 Prompt Injection"]},
    "injecagent": {"name": "InjecAgent", "kind": "external", "what": "1,054-case indirect prompt-injection benchmark (tool-integrated agents)", "owasp": ["LLM01 Prompt Injection", "LLM06 Excessive Agency"]},
    "agentdojo": {"name": "AgentDojo", "kind": "external", "what": "ETH Zürich prompt-injection attacks across banking/workspace/travel/slack", "owasp": ["LLM01 Prompt Injection", "LLM06 Excessive Agency"]},
    "asb": {"name": "ASB (Agent Security Bench)", "kind": "external", "what": "injected malicious attack-tools a compromised agent may call (resource hijack, stealthy exfiltration)", "owasp": ["LLM06 Excessive Agency", "LLM07 System Prompt Leakage"]},
    "cyberseceval": {"name": "CyberSecEval (prompt injection)", "kind": "external", "what": "Meta PurpleLlama input-side prompt-injection set (complementary screen)", "owasp": ["LLM01 Prompt Injection"]},
    "memory_integrity": {"name": "Memory integrity & drift", "kind": "kaizen-corpus", "what": "Kaizen adversarial corpus: memory poisoning + baseline deviation (ASB-aligned)", "owasp": ["LLM08 Vector and Embedding Weaknesses", "LLM06 Excessive Agency"]},
}


def main():
    benches = []
    for key in ORDER:
        p = os.path.join(RESULTS, key + ".json")
        if not os.path.exists(p):
            continue
        s = json.load(open(p))["summary"]
        m = META[key]
        benches.append({
            "key": key, "name": m["name"], "kind": m["kind"], "what": m["what"], "owasp": m["owasp"],
            "model": s.get("model"), "detection_tpr": s["detection_rate_tpr"],
            "false_positive_fpr": s["false_positive_rate_fpr"], "precision": s["precision"],
            "f1": s["f1"], "confusion": s["confusion"],
            "n": s.get("n") or s.get("scenarios") or s.get("sampled_cases"),
        })
    # aggregate confusion across all benchmarks
    agg = {"TP": 0, "FN": 0, "TN": 0, "FP": 0}
    for b in benches:
        for k in agg:
            agg[k] += b["confusion"].get(k, 0)
    tpr = agg["TP"] / (agg["TP"] + agg["FN"]) if (agg["TP"] + agg["FN"]) else 0
    fpr = agg["FP"] / (agg["FP"] + agg["TN"]) if (agg["FP"] + agg["TN"]) else 0
    out = {
        "generated_by": "kaizen-security/evals/aggregate.py",
        "model": "Claude Sonnet 4.6 on Amazon Bedrock (Kaizen runs on your own model)",
        "benchmarks": benches,
        "aggregate": {
            "n_benchmarks": len(benches),
            "total_attack_cases": agg["TP"] + agg["FN"],
            "total_benign_cases": agg["TN"] + agg["FP"],
            "overall_detection_tpr": round(tpr, 4),
            "overall_false_positive_fpr": round(fpr, 4),
            "confusion": agg,
        },
        "methodology": ("Each benchmark scenario is converted into Kaizen's action/egress format and "
                        "judged by the real in-sandbox detector logic with the shipping detection skills, "
                        "no per-case tuning. Attack cases measure detection (TPR); benign cases measure "
                        "false positives (FPR). External academic benchmarks and one Kaizen adversarial "
                        "corpus are labeled distinctly. Numbers regenerate from this harness."),
    }
    json.dump(out, open(os.path.join(RESULTS, "results.json"), "w"), indent=2)
    print(f"=== {len(benches)} benchmarks aggregated ===")
    for b in benches:
        print(f"  {b['name']:34} TPR {b['detection_tpr']:.0%}  FPR {b['false_positive_fpr']:.1%}  F1 {b['f1']:.2f}  ({b['kind']})")
    print(f"  {'OVERALL':34} TPR {tpr:.1%}  FPR {fpr:.1%}  over {agg['TP']+agg['FN']} attacks / {agg['TN']+agg['FP']} benign")
    print("wrote results/results.json")


if __name__ == "__main__":
    main()
