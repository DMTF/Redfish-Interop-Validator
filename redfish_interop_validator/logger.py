# Copyright Notice:
# Copyright 2017-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md

"""
Redfish Interop Validator Logger

File : logger.py

Brief : This file contains the definitions and functionalities for handling
        the debug log.
"""

import logging

logger = None


def log_print(*args, **kwargs):
    """
    Prints to the console and adds an INFO entry to the debug log
    Design note: Use this for printing to the console during testing

    Args:
        args: Positional arguments
        kwargs: Keyword arguments
    """
    if logger:
        logger.info(*args, **kwargs)
    print(*args, **kwargs)


def debug(*args, **kwargs):
    """
    Adds a DEBUG entry to the debug log
    Design note: Use this for debug tracing with --debugging turned on

    Args:
        args: Positional arguments
        kwargs: Keyword arguments
    """
    if logger:
        logger.debug(*args, **kwargs)


def info(*args, **kwargs):
    """
    Adds an INFO entry to the debug log
    Design note: Use this for debug tracing regardless of the usage of --debugging

    Args:
        args: Positional arguments
        kwargs: Keyword arguments
    """
    if logger:
        logger.info(*args, **kwargs)


def warning(*args, **kwargs):
    """
    Adds a WARNING entry to the debug log

    Args:
        args: Positional arguments
        kwargs: Keyword arguments
    """
    if logger:
        logger.warning(*args, **kwargs)


def error(*args, **kwargs):
    """
    Adds an ERROR entry to the debug log

    Args:
        args: Positional arguments
        kwargs: Keyword arguments
    """
    if logger:
        logger.error(*args, **kwargs)


def critical(*args, **kwargs):
    """
    Prints to the console and adds a CRITICAL entry to the debug log

    Args:
        args: Positional arguments
        kwargs: Keyword arguments
    """
    if logger:
        logger.critical(*args, **kwargs)
    print(*args, **kwargs)
