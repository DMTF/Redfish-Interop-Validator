# Copyright Notice:
# Copyright 2017-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md

"""
Redfish Validator Console Scripts

File : console_scripts.py

Brief : This file contains the definitions and functionalities for invoking
        the interop validator.
"""

import argparse
import colorama
import logging
import os
import redfish
import sys
from datetime import datetime
from pathlib import Path

from redfish_interop_validator.system_under_test import SystemUnderTest
from redfish_interop_validator import logger
from redfish_interop_validator import profile
from redfish_interop_validator import report
from redfish_interop_validator import validate

tool_version = '3.0.0'


def main():
    """
    Entry point for the service validator
    """

    # Get the input arguments
    argget = argparse.ArgumentParser(description="Validate Redfish services against profiles")
    argget.add_argument(
        "--user", "-u", "-user", "--username", type=str, required=True, help="The username for authentication"
    )
    argget.add_argument("--password", "-p", type=str, required=True, help="The password for authentication")
    argget.add_argument(
        "--rhost", "-r", "--ip", "-i", type=str, required=True, help="The address of the Redfish service (with scheme)"
    )
    argget.add_argument(
        "--authtype", type=str, default="Session", choices=["Basic", "Session"], help="The authorization type"
    )
    argget.add_argument(
        "--serv_http_proxy", type=str, help="The URL of the HTTP proxy for accessing the Redfish service"
    )
    argget.add_argument(
        "--serv_https_proxy", type=str, help="The URL of the HTTPS proxy for accessing the Redfish service"
    )
    argget.add_argument(
        "--logdir",
        "--report-dir",
        type=str,
        default="logs",
        help="The directory for generated report files; default: 'logs'",
    )
    argget.add_argument(
        "--payload",
        type=str,
        help="Controls how much of the data model to test; option is followed by the URI of the resource from which to start",
        nargs=2,
    )
    argget.add_argument(
        "--mockup", type=str, help="Path to directory containing mockups to override responses from the service"
    )
    argget.add_argument(
        "--collectionlimit",
        type=str,
        default=["LogEntry", "20"],
        help="Applies a limit to testing resources in collections; format: RESOURCE1 COUNT1 RESOURCE2 COUNT2 ...",
        nargs="+",
    )
    argget.add_argument("--nooemcheck", action="store_true", help="Don't check OEM items")
    argget.add_argument(
        "--timeout",
        "-timeout",
        type=int,
        help="The timeout, in seconds, for the service to respond to HTTP requests",
    )
    argget.add_argument(
        "--debugging",
        action="store_true",
        help="Controls the verbosity of the debugging output; if not specified only INFO and higher are logged",
    )
    argget.add_argument("profile", type=str, default="sample.json", help="The Redfish profile to use to verify the service")
    args = argget.parse_args()
    code, file = run_validator(vars(args))
    if code != 0:
        sys.exit(code)


def run_validator(args):
    # Set up the traversal mode
    if args["payload"]:
        traverse_mode, starting_uri = args["payload"]
    else:
        traverse_mode, starting_uri = None, "/redfish/v1/"

    # Get the current time for report files
    test_time = datetime.now()

    # Create report directory with timestamped subfolder (YYYY-MM-DD-HHMMSS)
    report_dir = Path(args["logdir"]) / test_time.strftime("%Y-%m-%d-%H%M%S")
    report_dir.mkdir(parents=True, exist_ok=True)

    # Set the logging level
    log_level = logging.INFO
    if args["debugging"]:
        log_level = logging.DEBUG
    log_file = report_dir / "RedfishInteropValidatorDebug_{}.log".format(test_time.strftime("%m_%d_%Y_%H%M%S"))
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    logger.logger = redfish.redfish_logger(log_file, log_format, log_level)
    logger.log_print("Redfish Interop Validator, Version {}\n".format(tool_version))
    logger.info("System: {}".format(args["rhost"]))
    logger.info("User: {}".format(args["user"]))

    # Read the requested profiles
    # Break out the profile directory from the profile argument
    profile_dir = os.path.dirname(args["profile"])
    if profile_dir == "":
        profile_dir = "."
    profile_file = os.path.basename(args["profile"])
    try:
        profile.load_profile(profile_dir, profile_file)
    except Exception as err:
        logger.critical("Aborting test; check previous messages for details")
        return 1, None

    # Set up the system
    try:
        sut = SystemUnderTest(
            args["rhost"],
            args["user"],
            args["password"],
            args["timeout"],
            args["authtype"],
            args["serv_http_proxy"],
            args["serv_https_proxy"],
            args["mockup"],
            args["collectionlimit"],
            args["nooemcheck"],
        )
    except Exception as err:
        logger.critical("Could not set up the service: {}".format(err))
        return 1, None

    # Validate the service
    sut.validate(traverse_mode, starting_uri, starting_uri)
    sut.apply_global_checks()

    # Results
    logger.log_print("")
    print_summary(sut)
    logger.log_print("")
    results_file = report.html_report(sut, report_dir, test_time, tool_version, args, profile.get_profile_name())
    xlsx_file = report.xlsx_report(sut, report_dir, test_time, tool_version, args, profile.get_profile_name())
    logger.log_print("HTML Report:  {}".format(results_file))
    logger.log_print("Excel Report: {}".format(xlsx_file))
    logger.log_print("Debug Log:    {}".format(log_file))
    logger.log_print("")

    sut.logout()

    return int(sut.fail_count > 0), str(results_file)


def summary_format(result, result_count):
    """
    Returns a color-coded result format

    Args:
        result: The type of result
        result_count: The number of results for that type
    """
    color_map = {
        "PASS": (colorama.Fore.GREEN, colorama.Style.RESET_ALL),
        "WARN": (colorama.Fore.YELLOW, colorama.Style.RESET_ALL),
        "FAIL": (colorama.Fore.RED, colorama.Style.RESET_ALL),
    }
    start, end = ("", "")
    if result_count:
        start, end = color_map.get(result, ("", ""))
    return start, result_count, end


def print_summary(sut):
    """
    Prints a stylized summary of the test results

    Args:
        sut: The system under test
    """
    colorama.init()
    pass_start, passed, pass_end = summary_format("PASS", sut.pass_count)
    warn_start, warned, warn_end = summary_format("WARN", sut.warn_count)
    fail_start, failed, fail_end = summary_format("FAIL", sut.fail_count)
    no_test_start, not_tested, no_test_end = summary_format("SKIP", sut.skip_count)

    col_w = 14
    sep = "+" + ("-" * col_w + "+") * 4
    header = "| {:^{w}} | {:^{w}} | {:^{w}} | {:^{w}} |".format("PASS", "WARN", "FAIL", "NOT TESTED", w=col_w - 2)
    values = "| {}{:^{w}}{} | {}{:^{w}}{} | {}{:^{w}}{} | {}{:^{w}}{} |".format(
        pass_start,
        str(passed),
        pass_end,
        warn_start,
        str(warned),
        warn_end,
        fail_start,
        str(failed),
        fail_end,
        no_test_start,
        str(not_tested),
        no_test_end,
        w=col_w - 2,
    )
    logger.log_print("")
    logger.log_print(sep)
    logger.log_print(header)
    logger.log_print(sep)
    logger.log_print(values)
    logger.log_print(sep)
    logger.log_print("")
    colorama.deinit()
