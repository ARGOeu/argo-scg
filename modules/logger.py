import logging
import logging.handlers

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
    logfile = logging.handlers.RotatingFileHandler(
        LOGFILE, maxBytes=512 * 1024, backupCount=5
    )
    logfile.setLevel(logging.INFO)
    logfile.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(logfile)

    return logger
