"""Collect explicitly enabled live TX and RTT jitter, without router writes."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import logging
from signal import SIGINT, SIGTERM, signal
from threading import Event
import time

from config import load_config
from services.deployment_service import validate_deployment
from services.json_storage import StorageError, StorageService
from services.live_samples import LiveSampleService


def next_sample_deadline(started, completed, interval):
    """A late batch resumes on completion, without waiting an extra whole tick."""
    return max(started + interval, completed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    config = load_config()
    validate_deployment(config)
    if config.get("SIMULATION_MODE") is not True or config.get("LIVE_ROUTING_ENABLED") is not False:
        raise SystemExit("Keep SIMULATION_MODE=true and LIVE_ROUTING_ENABLED=false.")
    storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
    storage.initialize()
    service = LiveSampleService(storage, config)
    stop = Event()
    for sig in (SIGINT, SIGTERM):
        signal(sig, lambda *_: stop.set())
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            while not stop.is_set():
                started = time.monotonic()
                try:
                    paths = storage.read_json("routing_paths.json")["paths"]
                    routers = sorted({p["aggregation_router_id"] for p in paths if p.get("live_sampling_enabled") is True})
                    service.close(keep=set(routers))
                    for future in [pool.submit(service.collect, rid) for rid in routers]:
                        future.result()
                except (StorageError, ValueError, OSError):
                    logging.error("Live sampling unavailable; review local monitoring settings.")
                    if args.once:
                        return 1
                if args.once:
                    return 0
                interval = config["LIVE_SAMPLE_INTERVAL_SECONDS"]
                now = time.monotonic()
                # Drop historical deadlines. A slightly late batch must not
                # introduce another full second of idle time before sampling.
                next_tick = next_sample_deadline(started, now, interval)
                stop.wait(max(0, next_tick - now))
    finally:
        service.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
