"""
Analyst-facing feedback loop.

  python feedback_cli.py review
      Walk through cases in data/triage_log.jsonl that need human review,
      confirm or correct the agent's verdict. Every response is captured via
      MemoryStore.capture_feedback (see agent/memory.py) - this both logs
      raw feedback AND immediately stores the closed case into the RAG
      'cases' collection for future retrieval.

  python feedback_cli.py distill
      Batch job (run nightly / weekly). Looks at recent disagreements and
      proposes candidate "lessons". YOU approve each one before it's written
      to the 'lessons' collection the live agent retrieves from - this is
      the human checkpoint that keeps self-improvement from drifting on
      noisy feedback.
"""
from __future__ import annotations
import json
import sys
import time
import uuid
from pathlib import Path

from agent.memory import MemoryStore

TRIAGE_LOG = Path("data/triage_log.jsonl")
REVIEWED_MARKER = Path("data/reviewed_case_ids.json")


def _load_reviewed() -> set[str]:
    if REVIEWED_MARKER.exists():
        return set(json.loads(REVIEWED_MARKER.read_text()))
    return set()


def _save_reviewed(ids: set[str]) -> None:
    REVIEWED_MARKER.write_text(json.dumps(sorted(ids)))


def review():
    if not TRIAGE_LOG.exists():
        print("No triage log yet - run main.py first.")
        return

    store = MemoryStore()
    reviewed = _load_reviewed()
    records = [json.loads(l) for l in TRIAGE_LOG.read_text().splitlines()]

    pending = [r for r in records if r["needs_human_review"]]
    print(f"{len(pending)} case(s) flagged for review.\n")

    for rec in pending:
        alert = rec["alert"]
        result = rec["result"]
        case_id = alert.get("alert_id", str(uuid.uuid4()))
        if case_id in reviewed:
            continue

        print(f"\n--- {case_id}: {alert.get('rule_name', alert.get('description'))} ---")
        print(f"Agent verdict: {result['verdict']} (confidence {result['confidence']:.2f})")
        print(f"Agent rationale: {result['rationale']}")
        print(f"Recommended action: {result['recommended_action']}")

        answer = input("\nAgree with verdict? [y/n/skip]: ").strip().lower()
        if answer == "skip":
            continue
        if answer == "y":
            analyst_verdict = result["verdict"]
            reasoning = input("Optional note (enter to skip): ").strip() or "Analyst confirmed agent verdict."
        else:
            analyst_verdict = input("Correct verdict [false_positive/true_positive/escalate]: ").strip()
            reasoning = input("Why? (this becomes training signal - be specific): ").strip()

        store.capture_feedback(case_id, alert, result, analyst_verdict, reasoning)
        reviewed.add(case_id)
        _save_reviewed(reviewed)
        print("Feedback captured.")

    print("\nReview complete.")


def distill():
    store = MemoryStore()
    # Look at all feedback ever captured; in production you'd pass the
    # timestamp of the last distill run instead of 0.
    candidates = store.distill_lessons(since_ts=0, min_records=3)

    if not candidates:
        print("No new generalizable lessons found (or not enough disagreement data yet).")
        return

    print(f"{len(candidates)} candidate lesson(s) found. Review each:\n")
    for c in candidates:
        print(f"\nProposed lesson: {c['lesson']}")
        print(f"Supporting cases: {c.get('supporting_case_ids', [])}")
        approve = input("Approve and add to agent memory? [y/n]: ").strip().lower()
        if approve == "y":
            store.approve_and_store_lesson(
                c["lesson"],
                {"supporting_case_ids": json.dumps(c.get("supporting_case_ids", [])), "added": time.time()},
            )
            print("Stored.")
        else:
            print("Skipped.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "review"
    if cmd == "review":
        review()
    elif cmd == "distill":
        distill()
    else:
        print("usage: python feedback_cli.py [review|distill]")
