"""Independent advisory calculation worker. Never connects to or configures routers."""
import argparse
import logging
import time
from signal import SIGINT, SIGTERM, signal
from threading import Event

from config import load_config
from services.json_storage import StorageError, StorageService
from services.workflow_service import WorkflowError, WorkflowService, optimization_enabled
from services.deployment_service import validate_deployment


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once',action='store_true',help='Calculate one advisory cycle and exit.')
    args=parser.parse_args(argv)
    config=load_config()
    validate_deployment(config)
    if config.get('LIVE_ROUTING_ENABLED') is not False or config.get('SIMULATION_MODE') is not True:
        raise SystemExit('Keep SIMULATION_MODE=true and LIVE_ROUTING_ENABLED=false for this advisory worker.')
    storage=StorageService(config['DATA_DIR'],config['OUTPUT_DIR'])
    storage.initialize()
    stop=Event()
    for sig in (SIGINT,SIGTERM): signal(sig,lambda *_:stop.set())
    next_calculation = 0.0
    previous_settings = None
    while not stop.is_set():
        try:
            settings=storage.read_json('automation_settings.json')
            if settings != previous_settings:
                next_calculation = 0.0
            previous_settings = settings
            interval=settings['monitoring_interval_seconds']
            if not optimization_enabled(settings):
                next_calculation = 0.0
                if args.once: print('Optimization is off. TX monitoring continues.')
            elif settings.get('optimization_objective')=='adaptive_mlu':
                if time.monotonic() >= next_calculation:
                    try:
                        result=WorkflowService(storage,config).calculate()
                    except WorkflowError:
                        # Off may have been saved after this worker read settings.
                        if optimization_enabled(storage.read_json('automation_settings.json')):
                            raise
                    else:
                        if args.once: print('Advisory optimization:',result['status'],'— routing changes remain off.')
                    next_calculation = time.monotonic() + interval
            elif args.once:
                print('Select Adaptive MLU in Settings to start automatic advisory calculations.')
        except (StorageError,WorkflowError,ValueError,OverflowError):
            logging.error('Advisory calculation unavailable; review local configuration and storage.')
            if args.once: return 1
            interval=60
        if args.once: return 0
        stop.wait(min(5,interval))
    return 0

if __name__=='__main__':
    raise SystemExit(main())
