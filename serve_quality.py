"""Collect opt-in RTT jitter over API-SSL. No routing or router configuration writes."""
import argparse
import logging
from signal import SIGINT, SIGTERM, signal
from threading import Event

from config import load_config
from services.deployment_service import validate_deployment
from services.json_storage import StorageError, StorageService
from services.link_quality import LinkQualityService


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    config = load_config()
    validate_deployment(config)
    if config.get("LIVE_ROUTING_ENABLED") is not False or config.get("SIMULATION_MODE") is not True:
        raise SystemExit("Keep SIMULATION_MODE=true and LIVE_ROUTING_ENABLED=false.")
    storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
    storage.initialize()
    service = LinkQualityService(storage, config)
    stop = Event()
    for sig in (SIGINT, SIGTERM):
        signal(sig, lambda *_: stop.set())
    while not stop.is_set():
        try:
            paths = storage.read_json("routing_paths.json")["paths"]
            for path in paths:
                if stop.is_set():
                    break
                if path.get("jitter_enabled") is True:
                    service.collect(path["path_id"])
        except (StorageError, OSError, ValueError):
            logging.error("RTT jitter monitoring unavailable; review local configuration and storage.")
            if args.once:
                return 1
        if args.once:
            return 0
        stop.wait(5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
