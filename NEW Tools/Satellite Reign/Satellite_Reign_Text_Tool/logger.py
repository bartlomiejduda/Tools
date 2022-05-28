"""
Copyright © 2022  Bartłomiej Duda
License: GPL-3.0 License
"""

import logging


def get_logger(name):
    logger = logging.getLogger(name)

    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler("log.txt")
    logger.setLevel(logging.DEBUG)

    log_format = (
        "%(asctime)s - %(name)s - line %(lineno)d - %(levelname)s - %(message)s"
    )
    datetime_format = "%Y-%m-%d %H:%M:%S"
    c_format = logging.Formatter(log_format, datetime_format)
    f_format = logging.Formatter(log_format, datetime_format)
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    logger.addHandler(c_handler)
    logger.addHandler(f_handler)

    return logger
