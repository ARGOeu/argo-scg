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
    #logfile = get_logfile_handler()
    #logger.addHandler(logfile)

    # setting up logging to syslog
    syslog = get_syslog_handler()
    logger.addHandler(syslog)

    return logger

def get_logfile_handler() -> logging.handlers.RotatingFileHandler:
    logfile = logging.handlers.RotatingFileHandler(
        LOGFILE, maxBytes=1 * 1024 * 1024, backupCount=10
    )
    logfile.setLevel(logging.INFO)
    logfile.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    ))

    return logfile

def get_syslog_handler() -> logging.handlers.SysLogHandler:
    syslog = logging.handlers.SysLogHandler()
    syslog.setLevel(logging.INFO)
    syslog.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    ))

    return syslog