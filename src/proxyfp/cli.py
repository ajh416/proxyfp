from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer

from proxyfp import fingerprint, store
from proxyfp.score import group_by_target, score_target

app = typer.Typer(add_completion=False, help="Fingerprint proxy sites and submit to Palo Alto.")
pan_app = typer.Typer(help="Palo Alto submission commands.")
app.add_typer(pan_app, name="pan")


@app.command("fingerprint")
def cmd_fingerprint(
    input_file: Path = typer.Option(..., "--input", "-i", help="File with one URL/domain per line."),
    concurrency: int = typer.Option(8, "--concurrency", "-c"),
) -> None:
    """Run all detectors against every target in INPUT_FILE."""
    targets = input_file.read_text().splitlines()
    asyncio.run(fingerprint.fingerprint_all(targets, concurrency=concurrency))
    print(f"Wrote probes to {store.PROBES}")


@app.command("score")
def cmd_score() -> None:
    """Score probes and split into auto-submit / review queues."""
    probes = list(store.read(store.PROBES))
    if not probes:
        print("No probes found. Run `proxyfp fingerprint` first.")
        raise typer.Exit(1)

    canary_hits = asyncio.run(fingerprint.refresh_canary_hits())
    grouped = group_by_target(probes)

    auto: list[dict] = []
    review: list[dict] = []
    dropped = 0
    for target, rows in grouped.items():
        s = score_target(rows, canary_hits=canary_hits)
        row = {"target": target, "score": s.score, "bucket": s.bucket, "contributing": s.contributing}
        if s.bucket == "auto_submit":
            auto.append(row)
        elif s.bucket == "review":
            review.append(row)
            store.append(store.REVIEW, row)
        else:
            dropped += 1

    Path("state").mkdir(exist_ok=True)
    Path("state/auto_submit.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in auto) + ("\n" if auto else "")
    )
    print(f"auto_submit: {len(auto)}  review: {len(review)}  dropped: {dropped}")


@app.command("review")
def cmd_review() -> None:
    """Print pending review items (one per line)."""
    for row in store.read(store.REVIEW):
        print(json.dumps(row, sort_keys=True))


@pan_app.command("login")
def cmd_pan_login() -> None:
    """Headed browser login — captures session for subsequent submissions."""
    from proxyfp.pan.login import login

    login()


@pan_app.command("submit")
def cmd_pan_submit(
    dry_run: bool = typer.Option(False, "--dry-run", help="Fill the form and screenshot, but don't click Submit."),
    throttle: int = typer.Option(30, "--throttle", help="Seconds between submissions."),
    source: Path = typer.Option(Path("state/auto_submit.jsonl"), "--source"),
) -> None:
    """Submit queued targets to Palo Alto."""
    from proxyfp.pan.submit import submit_queue

    if not source.exists():
        print(f"{source} not found — run `proxyfp score` first.", file=sys.stderr)
        raise typer.Exit(1)

    queue = [json.loads(line) for line in source.read_text().splitlines() if line.strip()]
    submit_queue(queue, dry_run=dry_run, throttle_s=throttle)


if __name__ == "__main__":
    app()
