"""Measure tool selection and argument accuracy of the configured LLM.

Each line of eval/cases.jsonl is a natural-language request with the tool the
agent should call and a subset of the arguments it should pass. The agent runs
against the real endpoint from `.env` (LLM_BASE_URL, LLM_API_KEY, LLM_MODEL);
results are written to eval/results/ (git-ignored).

Usage:
    python eval/run_eval.py [--delay 3] [--only build-linux-web,list]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agent import LLMError, run_agent  # noqa: E402
from app.attack import load_attack  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.evaluation import score_case, summarise  # noqa: E402
from app.library import load_library  # noqa: E402
from app.tools import ToolContext  # noqa: E402

EVAL_DIR = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--cases", default=str(EVAL_DIR / "cases.jsonl"))
    parser.add_argument(
        "--delay", type=float, default=2.0, help="seconds between cases (free-tier rate limits)"
    )
    parser.add_argument("--only", help="comma-separated case IDs")
    args = parser.parse_args()

    settings = get_settings()
    if not settings.llm_configured:
        print("LLM_API_KEY is not set (see .env.example)")
        return 2
    cases = [
        json.loads(line) for line in Path(args.cases).read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if args.only:
        wanted = set(args.only.split(","))
        cases = [c for c in cases if c["id"] in wanted]

    attack, library = load_attack(), load_library()
    scores, runs = [], []
    print(f"Model {settings.llm_model} @ {settings.llm_base_url}, {len(cases)} cases")
    for i, case in enumerate(cases):
        if i:
            time.sleep(args.delay)
        started = time.perf_counter()
        try:
            result = run_agent(case["question"], ToolContext(attack, library), settings)
            score = score_case(case, result)
        except LLMError as exc:
            result, score = {"error": str(exc)}, {"id": case["id"], "kind": "error", "error": str(exc)}
        score["seconds"] = round(time.perf_counter() - started, 1)
        scores.append(score)
        runs.append(
            {"case": case, "answer": result.get("answer"), "trace": result.get("trace"), "score": score}
        )
        if score["kind"] == "tool":
            mark = "ok " if score["args_ok"] else ("~  " if score["tool_ok"] else "XX ")
        elif score["kind"] == "refusal":
            mark = "ok " if score["passed"] else "XX "
        else:
            mark = "ERR"
        print(
            f"  {mark} {case['id']:<22} tools={score.get('tools', score.get('error'))}  {score['seconds']} s"
        )

    summary = summarise(scores)
    print(json.dumps(summary, indent=2))
    out_dir = EVAL_DIR / "results"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"{datetime.now(UTC):%Y%m%d-%H%M%S}-{settings.llm_model.replace('/', '_')}.json"
    out.write_text(
        json.dumps({"model": settings.llm_model, "summary": summary, "runs": runs}, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
