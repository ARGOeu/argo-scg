import logging
from logging.handlers import TimedRotatingFileHandler
import shutil
import os
import gzip

LOGFILE = "/var/log/argo-scg/argo-scg.log"
LOGNAME = "argo-scg"

def get_logger():
    logger = logging.getLogger(LOGNAME)
    logger.setLevel(logging.INFO)

    # setting up stdout
    stdout = logging.StreamHandler()
    stdout.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
    logger.addHandler(stdout)

    # setting up logging to a file
    logfile = _create_log_file_handler(LOGFILE)
    logger.addHandler(logfile)

    return logger

def _create_log_file_handler(in_file_name: str) -> TimedRotatingFileHandler:    
    log_file = TimedRotatingFileHandler(
       LOGFILE,
       when="midnight",
       utc=False,
       delay=False,
       backupCount=365
    ) 

    # setup for compression
    log_file.namer = _gz_namer
    log_file.rotator = _gzip_rotator

    log_file.setLevel(logging.INFO)
    log_file.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    ))

    return log_file

def _gz_namer(default_name):
    # Tell the handler that the rotated filename ends in .gz
    return default_name + ".gz"


def _gzip_rotator(source, dest):
    # source is the old log file; dest already ends in .gz
    with open(source, "rb") as src, gzip.open(dest, "wb") as dst:
        shutil.copyfileobj(src, dst)
    os.remove(source)