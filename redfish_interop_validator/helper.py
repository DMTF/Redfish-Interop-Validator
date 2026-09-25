# Copyright Notice:
# Copyright 2017-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md

"""
Helper

File : helper.py

Brief : This file contains common helper functions.
"""

import re

from redfish_interop_validator import logger

# Regex fragment used in profile filename matching (Namespace.v1_2_3.Type)
_VERSION_PATTERN = r"\.(v([0-9]+)_([0-9]+)_([0-9]+))\."

# Regex used to expand URI templates in profiles such as
# ``/redfish/v1/Chassis/{ChassisId}`` when comparing against real URIs.
_URI_ID_PATTERN = r"{[A-Za-z0-9]+}"
_VALID_ID_PATTERN = r"[^\/]+"


def get_version(in_string):
    """
    Gets the version information from a string

    Args:
        in_string: The string to parse

    Returns:
        A string containing the version in the form 'vX.Y.Z'
        A tuple containing the version as (X, Y, Z)
    """
    version_str = None
    version = None
    try:
        groups = re.search(_VERSION_PATTERN, in_string)
        if groups:
            version_str = groups.group(1).replace("_", ".")
            version = (int(groups.group(2)), int(groups.group(3)), int(groups.group(4)))
    except:
        pass

    return version_str, version


def uri_check(expected_uris, uri):
    """
    Check if a URI matches any of the expected URIs in a profile.

    Args:
        expected_uris: List of expected URIs from the profile
        uri: The URI to check

    Returns:
        True if the URI matches any of the expected URIs, False otherwise
    """
    if not expected_uris:
        # No expected URIs means any URI is acceptable
        return True

    # Join the expected URIs into a single pattern and check if the URI matches
    pattern = "^{}$".format("|".join(expected_uris))
    pattern = re.sub(_URI_ID_PATTERN, _VALID_ID_PATTERN, pattern)
    return re.fullmatch(pattern, uri) is not None


def find_property(property_name, payload, payload_full):
    """
    Finds a property in the payload

    Args:
        property_name: The name of the property to find
        payload: The local JSON object making the property reference
        payload_full: The entire payload to search if required

    Returns:
        A boolean indicating if the property was found
        The value of the property if found, None otherwise
    """
    if property_name.startswith("/"):
        # Look for the property in the full payload using JSON pointer
        try:
            # Remove the leading '/' and split by '/'
            parts = property_name[1:].split("/")

            # Navigate through the full payload
            current = payload_full
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                elif isinstance(current, list):
                    try:
                        index = int(part)
                        if 0 <= index < len(current):
                            current = current[index]
                        else:
                            return False, None
                    except ValueError:
                        return False, None
                else:
                    return False, None

            return True, current
        except:
            return False, None
    else:
        # Not a JSON pointer; check root level of the local object
        if isinstance(payload, dict) and property_name in payload:
            return True, payload[property_name]
        else:
            return False, None


def evaluate_comparison(sut, compare_property, compare_type, compare_values, payload, payload_full):
    """
    Evaluates a comparison condition

    Args:
        sut: The system under test
        compare_property: The name of the property to compare
        compare_type: The type of comparison to perform
        compare_values: The values to compare against
        payload: The local JSON object making the property reference
        payload_full: The entire payload to search if required

    Returns:
        A string containing the error message if the comparison failed, None otherwise
    """
    # Find the property value
    found, value = find_property(compare_property, payload, payload_full)
    result = "Comparison Error: Comparison doesn't apply"

    # Log message to console if values is empty
    if compare_type != "Absent" and compare_type != "Present":
        if len(compare_values) == 0:
            logger.critical(
                "Comparison values is empty for the property {} with comparison type {}".format(
                    compare_property, compare_type
                )
            )

    if found:
        # Convert a singleton value to an array to leverage existing array validation logic
        test_val = value
        if not isinstance(test_val, list):
            test_val = [test_val]

        for value_under_test in test_val:
            if compare_type == "Present":
                # Value doesn't need to be checked
                result = None
                break

            if compare_type in ["AnyOf", "Equal", "Pattern", "LinkToResource"]:
                # For these comparisons, the value needs to match at least one of the expected values

                # Set up failure strings
                fail_strings = {
                    "AnyOf": "Comparison Error: The property does not contain one of the expected values: {}".format(
                        ", ".join(compare_values)
                    ),
                    "Equal": "Comparison Error: The property does not contain one of the expected values: {}".format(
                        ", ".join(compare_values)
                    ),
                    "LinkToResource": "Comparison Error: The property does not link to a resource of the expected types: {}".format(
                        ", ".join(compare_values)
                    ),
                    "Pattern": "Comparison Error: The property does not match one of the expected patterns: {}".format(
                        ", ".join(compare_values)
                    ),
                }

                # Need to find at least one match in the comparison list
                match = False
                for compare_val in compare_values:
                    if compare_type == "Equal":
                        if compare_val == value_under_test:
                            match = True
                            break
                    elif compare_type == "LinkToResource":
                        # Need to ensure the value is a proper reference object; we also skip external references since we do not have credentials to access them
                        if "@odata.id" in value_under_test:
                            if isinstance(value_under_test["@odata.id"], str) and value_under_test[
                                "@odata.id"
                            ].startswith("/"):
                                linked_type, _, _ = sut.get_resource_type(value_under_test["@odata.id"])
                                if linked_type is not None and linked_type in compare_values:
                                    match = True
                                    break
                            else:
                                result = "Comparison Error: The property does not contain a valid URI"
                        else:
                            result = "Comparison Error: The property does not contain a valid reference object"
                    elif compare_type == "Pattern":
                        if re.match(compare_val, value_under_test):
                            match = True
                            break
                if match:
                    result = None
                else:
                    result = fail_strings.get(
                        compare_type, "Comparison Error: The property does not meet the comparison requirements"
                    )

            elif compare_type in ["NotEqual", "GreaterThan", "GreaterThanOrEqual", "LessThan", "LessThanOrEqual"]:
                # For these comparisons, the value needs to match all of the requirements

                result = None
                for compare_val in compare_values:
                    if compare_type == "NotEqual":
                        if compare_val == value_under_test:
                            result = "Comparison Error: The property contains '{}', but is not allowed".format(
                                compare_val
                            )
                    elif compare_type == "GreaterThan":
                        if value_under_test <= compare_val:
                            result = "Comparison Error: The property value '{}' is not greater than '{}'".format(
                                value_under_test, compare_val
                            )
                    elif compare_type == "GreaterThanOrEqual":
                        if value_under_test < compare_val:
                            result = (
                                "Comparison Error: The property value '{}' is not greater than or equal to '{}'".format(
                                    value_under_test, compare_val
                                )
                            )
                    elif compare_type == "LessThan":
                        if value_under_test >= compare_val:
                            result = "Comparison Error: The property value '{}' is not less than '{}'".format(
                                value_under_test, compare_val
                            )
                    elif compare_type == "LessThanOrEqual":
                        if value_under_test > compare_val:
                            result = (
                                "Comparison Error: The property value '{}' is not less than or equal to '{}'".format(
                                    value_under_test, compare_val
                                )
                            )

            elif compare_type in ["Range"]:
                # Need to check each value meets the range requirements

                # Pad out the range requirements; it can have at most 3 members, and 'None' is used to indicate special meanings
                range_req = compare_values
                if len(range_req) < 3:
                    range_req.extend([None] * (3 - len(range_req)))

                # range_req[0] is the minimum value
                # range_req[1] is the maximum value
                # range_req[2] is the nominal value

                result = None
                nominal_val_str = ""
                if range_req[2] != None:
                    nominal_val_str = " (nominal value: {})".format(range_req[2])

                if range_req[0] != None:
                    if value_under_test < range_req[0]:
                        result = "Comparison Error: The property value '{}' is below the minimum allowed value '{}'{}".format(
                            value_under_test, range_req[0], nominal_val_str
                        )

                if range_req[1] != None:
                    if value_under_test > range_req[1]:
                        result = "Comparison Error: The property value '{}' is above the maximum allowed value '{}'{}".format(
                            value_under_test, range_req[1], nominal_val_str
                        )
    else:
        if compare_type == "Absent":
            # Absence of the property is the only check
            result = None

    return result
