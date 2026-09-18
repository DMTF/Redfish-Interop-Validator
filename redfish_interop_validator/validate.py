# Copyright Notice:
# Copyright 2017-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md

"""
Validate

File : validate.py

Brief : This file contains the definitions and functionalities for validating
        validating Redfish payloads against Redfish profiles.
"""

import re
from enum import IntEnum

from redfish_interop_validator import helper
from redfish_interop_validator import logger
from redfish_interop_validator import profile


class Result(IntEnum):
    SKIP = 1
    PASS = 2
    WARN = 3
    FAIL = 4


def validate_response(resource):
    """
    Performs basic validation of a response prior to any detailed JSON inspections

    Args:
        resource: The resource to validate

    Returns:
        A dictionary of the JSON payload contents of the response; None if invalid
    """
    if resource["Response"] is None:
        # We need a response...
        return None
    if resource["Response"].status != 200:
        # The response need to return a 200...
        return None
    payload = None
    try:
        payload = resource["Response"].dict
    except:
        # The response needs to pass JSON parsing...
        return None
    if not isinstance(payload, dict):
        # The response needs to be a JSON object...
        return None

    return payload


def validate_resource(sut, use_case, uri, payload_full):
    """
    Validates resource-level requirements for a URI

    Args:
        sut: The system under test
        use_case: The use case to validate
        uri: The URI under test
        payload_full: The entire payload from the resource
    """
    # Apply conditional checks to the requirement
    requirement = evaluate_conditional(sut, use_case, uri, payload_full, payload_full)
    
    # Min version check
    min_ver_req = ".v" + requirement.get("MinVersion", "1.0.0").replace(".", "_") + "."
    min_ver_str, min_ver = helper.get_version(min_ver_req)
    _, resource_ver_str, resource_ver = sut.get_resource_type(uri)
    if resource_ver is not None:
        if resource_ver < min_ver:
            sut.add_property_result(uri, "", True, "", (Result.FAIL, "Resource Version Error: The resource version ({}) is lower than the minimum version required by the profile ({})".format(resource_ver_str, min_ver_str)))

    # Allow header check
    allow_header = sut.get_allow_header(uri)
    allow_header_split = None
    if allow_header:
        allow_header_split = [allow.strip().upper() for allow in allow_header.split(",")]
    if allow_header_split is not None:
        if use_case.get("CreateResource", False):
            if "POST" not in allow_header_split:
                sut.add_property_result(uri, "", True, "", (Result.FAIL, "Resource Capabilities Error: 'POST' not found in the Allow header"))
        #if use_case.get("DeleteResource", False):
        #    if "DELETE" not in allow_header_split:
        #        sut.add_property_result(uri, "", True, "", (Result.FAIL, "Resource Capabilities Error: 'DELETE' not found in the Allow header"))
        #if use_case.get("UpdateResource", False):
        #    if "PUT" not in allow_header_split and "PATCH" not in allow_header_split:
        #        sut.add_property_result(uri, "", True, "", (Result.FAIL, "Resource Capabilities Error: 'PUT' or 'PATCH' not found in the Allow header"))
    else:
        if use_case.get("CreateResource", False) or use_case.get("DeleteResource", False) or use_case.get("UpdateResource", False):
            sut.add_property_result(uri, "", True, "", (Result.WARN, "Resource Capabilities Warning: No Allow header found"))

def validate_properties(sut, use_case, uri, payload, payload_full, prop_path):
    """
    Validates the properties of a JSON object in a response

    Args:
        sut: The system under test
        use_case: The use case to validate
        uri: The URI under test
        payload: The JSON object to validate as a dictionary
        payload_full: The entire payload from the resource
        prop_path: The property path from the root of the response to this object
    """
    # Go through each property in the use case
    for prop in use_case:
        cur_path = prop_path + "/" + prop
        cur_path_wr = cur_path + " (Write)"

        # Apply conditional checks to the requirement
        requirement = evaluate_conditional(sut, use_case[prop], uri, payload, payload_full)

        # Replaced by; skip if the newer property is present
        if "ReplacedByProperty" in requirement:
            found, _ = helper.find_property(requirement["ReplacedByProperty"], payload, payload_full)
            if found:
                continue

        # Replaces; skip if the older property is present and the newer property is missing
        if "ReplacesProperty" in requirement and prop not in payload:
            found, _ = helper.find_property(requirement["ReplacesProperty"], payload, payload_full)
            if found:
                continue

        # Initial read requirement testing
        read_requirement = requirement.get("ReadRequirement", "Mandatory")
        if read_requirement == "IfPopulated":
            # Check if the resource is indicating presence; this can elevate the requirement
            _, resource_state = helper.find_property("/Status/State", payload, payload_full)
            if resource_state != "Absent":
                read_requirement = "Mandatory"
        if read_requirement in ["Conditional", "None", "IfPopulated"]:
            # No requirement defined
            continue
        elif read_requirement == "Excluded" and prop in payload:
            # Not allowed
            sut.add_property_result(uri, cur_path, False, None, (Result.FAIL, "Read Requirement Error: The property '{}' is not allowed".format(prop)))
        elif read_requirement in ["Recommended", "IfImplemented"] and prop not in payload:
            sut.add_property_result(uri, cur_path, False, None, (Result.SKIP, "Skip: The property is not present"))
        elif read_requirement == "Supported":
            if prop not in payload:
                sut.add_property_result(uri, cur_path, False, None, (Result.SKIP, "Skip: The property is not present"))
            sut.add_global_value_check(uri, cur_path, prop in payload, "ReadSupport", [True])
        elif prop not in payload:
            # Mandatory but not present
            sut.add_property_result(uri, cur_path, False, None, (Result.FAIL, "Read Requirement Error: The property '{}' is not present".format(prop)))

        if prop not in payload:
            continue

        # Mark it as passed; this will be cleared out as testing progresses when errors are found
        sut.add_property_result(uri, cur_path, True, payload[prop], (Result.PASS, "Property present"))

        # Write requirement; check if the property is writable
        write_requirement = requirement.get("WriteRequirement", "None")
        if write_requirement != "None":
            # Get the Allow header for initial smell testing
            allow_header = sut.get_allow_header(uri)
            resource_writable = None
            if allow_header:
                allow_header_split = [allow.strip().upper() for allow in allow_header.split(",")]
                resource_writable = "PUT" in allow_header_split or "PATCH" in allow_header_split
            if resource_writable is False:
                # Allow header is present and does not support PUT or PATCH
                if write_requirement == "Mandatory":
                    sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.FAIL, "Write Requirement Error: The resource is not writable"))
                else:
                    sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.SKIP, "Skip: The resource is not writable"))
                    if write_requirement == "Supported":
                        sut.add_global_value_check(uri, cur_path_wr, False, "WriteSupport", [True])
            elif "@Redfish.WriteableProperties" in payload:
                # Check @Redfish.WriteableProperties  to see if the property is called out
                # Yes, 'writeable' is not the correct spelling, but this is how it's called out in the spec
                if prop not in payload["@Redfish.WriteableProperties"]:
                    if write_requirement == "Mandatory":
                        sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.FAIL, "Write Requirement Error: The property is not writable"))
                    else:
                        sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.SKIP, "Skip: The property is not writable"))
                        if write_requirement == "Supported":
                            sut.add_global_value_check(uri, cur_path_wr, False, "WriteSupport", [True])
                else:
                    sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.PASS, "Pass: The property is writable"))
                    if write_requirement == "Supported":
                        sut.add_global_value_check(uri, cur_path_wr, True, "WriteSupport", [True])
            else:
                sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.SKIP, "Skip: Cannot test"))
                if write_requirement == "Supported":
                    sut.add_global_value_check(uri, cur_path_wr, None, "WriteSupport", [True])

        # Min count; basic array length check
        if "MinCount" in requirement:
            if isinstance(payload[prop], list):
                if len(payload[prop]) < requirement["MinCount"]:
                    sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.FAIL, "Min Count Error: The array contains {} elements, but requires at least {}".format(len(payload[prop]), requirement["MinCount"])))
            else:
                sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.WARN, "Min Count Error: The property is not an array"))

        # Supported values; check the @Redfish.AllowableValues property to see what's supported
        if "MinSupportValues" in requirement:
            print(cur_path)
            allow_values = prop + "@Redfish.AllowableValues"
            if allow_values in payload:
                if isinstance(payload[allow_values], list):
                    for req_value in requirement["MinSupportValues"]:
                        if req_value not in payload[allow_values]:
                            sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.FAIL, "Supported Values Error: The value '{}' is not supported".format(req_value)))
                else:
                    sut.add_property_result(uri, cur_path_wr, True, payload[prop], (Result.WARN, "Supported Values Error: '{}' is not an array".format(allow_values)))

        # Comparison
        if "Values" in requirement:
            comparison = requirement.get("Comparison", "AnyOf")
            if comparison in ["AnyOf", "AllOf"]:
                sut.add_global_value_check(uri, cur_path, payload[prop], comparison, requirement["Values"])
            else:
                # Other comparisons are evaluated now
                result = helper.evaluate_comparison(sut, cur_path, comparison, requirement["Values"], payload, payload_full)
                if result is not None:
                    sut.add_property_result(uri, cur_path, True, payload[prop], (Result.FAIL, result))

        # Property requirements; validate nested properties
        if "PropertyRequirements" in requirement:
            if isinstance(payload[prop], list):
                # An array; validate the members
                for i, array_value in enumerate(payload[prop]):
                    curr_array_path = cur_path + "/" + str(i)
                    if isinstance(array_value, dict):
                        validate_properties(sut, requirement["PropertyRequirements"], uri, array_value, payload_full, curr_array_path)
                    elif array_value is not None:
                        # Log warning; possibly bad profile, possibly bad service (supposed to be an object or array of objects)
                        sut.add_property_result(uri, cur_path, True, payload[prop], (Result.WARN, "Property Requirements Warning: Unexpected non-object value in array"))
            elif isinstance(payload[prop], dict):
                validate_properties(sut, requirement["PropertyRequirements"], uri, payload[prop], payload_full, cur_path)
            else:
                # Log warning; possibly bad profile, possibly bad service (supposed to be an object or array of objects)
                sut.add_property_result(uri, cur_path, True, payload[prop], (Result.WARN, "Property Requirements Warning: Unexpected non-object value"))

    return

def evaluate_conditional(sut, requirement, uri, payload, payload_full):
    """
    Evaluates a conditional requirement
    
    Args:
        sut: The system under test
        requirement: The conditional requirement to evaluate
        uri: The URI under test
        payload: The local JSON object making the property reference
        payload_full: The entire payload to search if required
    
    Returns:
        A property requirement structure post conditional evaluation
    """
    if "ConditionalRequirements" not in requirement:
        # Nothing to evaluate
        return requirement

    for condition in requirement["ConditionalRequirements"]:
        # Check if there is a URI match
        if "URIs" in condition:
            if not helper.uri_check(condition["URIs"], uri):
                # URI doesn't match, skip this condition
                continue

        # Check if there is a subordinate resource match
        if "SubordinateToResource" in condition:
            uri_split = uri.split("/")
            no_match = False
            for parent_resource in reversed(condition["SubordinateToResource"]):
                if len(uri_split) < 3:
                    # Prevent going higher than service root
                    no_match = True
                    break
                del uri_split[-1]

                # Get the parent URI and check its type
                parent_uri = "/" + "/".join(uri_split)
                parent_type, _, _ = sut.get_resource_type(parent_uri)
                if parent_type != parent_resource:
                    no_match = True
                    break
            if no_match is True:
                # Parent resource types don't match, skip this condition
                continue

        # Check if there is a property match
        if "CompareProperty" in condition and "CompareType" in condition:
            result = helper.evaluate_comparison(sut, condition["CompareProperty"], condition["CompareType"], condition.get("CompareValues", []), payload, payload_full)
            if result is not None:
                # Property value doesn't match, skip this condition
                continue

        # If we get here, a matching condition was found; return a modified requirement
        updated_requirement = dict(requirement)
        updated_requirement["ReadRequirement"] = condition.get("ReadRequirement", "Mandatory")
        updated_requirement["WriteRequirement"] = condition.get("WriteRequirement", "None")
        for req_prop in ["Purpose", "Values", "Comparison"]:
            updated_requirement.pop(req_prop, None)
            if req_prop in condition:
                updated_requirement[req_prop] = condition[req_prop]
        return updated_requirement

    # No matches; just use the existing requirement    
    return requirement

def validate_actions(sut, use_case, uri, resource_type, payload_full):
    """
    Validates the actions in a response

    Args:
        sut: The system under test
        use_case: The use case to validate
        uri: The URI under test
        resource_type: The type of the resource
        payload_full: The entire payload from the resource
    """
    # Go through each action in the use case
    for action in use_case:
        # Extract the requirements
        read_requirement = use_case[action].get("ReadRequirement", "Mandatory")
        action_info_requirement = use_case[action].get("ActionInfo", "None")
        action_path = "/Actions/#{}.{}".format(resource_type, action)
        action_info_path = action_path + "/@Redfish.ActionInfo"
        action_info_path_results = action_path + " (Action Info)"
        if read_requirement == "None":
            # No requirement; skip
            continue

        # Get the action object
        action_found, action_obj = helper.find_property(action_path, {}, payload_full)
        if not action_found:
            # Action not found
            if read_requirement == "Mandatory":
                sut.add_property_result(uri, action_path, False, None, (Result.FAIL, "Required Action Error: The action '{}' is mandatory".format(action)))
            elif read_requirement == "Recommended":
                sut.add_property_result(uri, action_path, False, None, (Result.SKIP, "Skip: The action is not present"))
        else:
            # Action found, validate it
            # Mark it as passed; this will be cleared out as testing progresses when errors are found
            sut.add_property_result(uri, action_path, True, action_obj, (Result.PASS, "Action present"))

            # Check for ActionInfo if needed
            if action_info_requirement != "None":
                action_info_found, action_info_val = helper.find_property(action_info_path, {}, payload_full)
                if not action_info_found:
                    if action_info_requirement == "Mandatory":
                        sut.add_property_result(uri, action_info_path_results, False, None, (Result.FAIL, "Required Action Info Error: The action info is mandatory"))
                    else:
                        sut.add_property_result(uri, action_info_path_results, False, None, (Result.SKIP, "Skip: The action info is not present"))
                else:
                    sut.add_property_result(uri, action_info_path_results, True, action_info_val, (Result.PASS, "Action info present"))
