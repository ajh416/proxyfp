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

    grouped = group_by_target(probes)

    auto: list[dict] = []
    review: list[dict] = []
    dropped = 0
    for target, rows in grouped.items():
        s = score_target(rows)
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
    """Headed browser login. Captures session for subsequent submissions."""
    from proxyfp.pan.login import login

    login()


@pan_app.command("submit")
def cmd_pan_submit(
    dry_run: bool = typer.Option(False, "--dry-run", help="Fill the form and screenshot, but don't click Submit."),
    throttle_min: float = typer.Option(3.0, "--throttle-min", help="Minimum seconds between submissions."),
    throttle_max: float = typer.Option(15.0, "--throttle-max", help="Maximum seconds between submissions."),
    source: Path = typer.Option(Path("state/auto_submit.jsonl"), "--source"),
) -> None:
    """Submit queued targets to Palo Alto."""
    from proxyfp.pan.submit import submit_queue

    if not source.exists():
        print(f"{source} not found. Run `proxyfp score` first.", file=sys.stderr)
        raise typer.Exit(1)

    queue = [json.loads(line) for line in source.read_text().splitlines() if line.strip()]
    submit_queue(queue, dry_run=dry_run, throttle_min_s=throttle_min, throttle_max_s=throttle_max)


if __name__ == "__main__":
    app()
