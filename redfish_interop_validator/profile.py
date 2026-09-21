# Copyright Notice:
# Copyright 2017-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md

"""
Profile

File : profile.py

Brief : This file contains the definitions and functionalities for parsing
        Redfish profiles (DSP0272).
"""

import json
import jsonschema
import os
import re

from redfish_interop_validator import helper
from redfish_interop_validator import logger
from redfish_interop_validator import profile_schema

_parsed_profiles = []
_use_case_id_counter = 0


class RedfishProfile:
    """
    Class for describing the contents of a Redfish profile

    Args:
        file_content: The content of the profile's JSON document
        filename: The name of the profile file
    """

    def __init__(self, file_content, filename):
        self._filename = filename
        self._raw = json.loads(file_content)
        self._required_profiles = []
        self._profile_name = filename
        global _use_case_id_counter

        # Build the human readable profile name
        if "ProfileName" in self._raw and "ProfileVersion" in self._raw:
            self._profile_name = self._raw["ProfileName"] + " (v" + self._raw["ProfileVersion"] + ")"

        if "Resources" in self._raw:
            for resource in self._raw["Resources"]:
                # Add a "default" use case for resources that don't specify any
                # This is to keep the validator from having to dynamically check if there is or isn't a use case
                if "UseCases" not in self._raw["Resources"][resource]:
                    default_use_case = dict(self._raw["Resources"][resource])
                    default_use_case["UseCaseTitle"] = "Default"
                    default_use_case["IsDefault"] = True
                    self._raw["Resources"][resource] = {}
                    self._raw["Resources"][resource]["UseCases"] = [default_use_case]

                # Build up records to track service-level requirements for all resources
                for i, use_case in enumerate(self._raw["Resources"][resource]["UseCases"]):
                    if "UseCaseTitle" not in use_case:
                        use_case["UseCaseTitle"] = "Use Case {}".format(i+1)
                    if "ReadRequirement" not in use_case:
                        use_case["ReadRequirement"] = "Mandatory"
                    use_case["Resource"] = resource
                    use_case["ProfileName"] = self._profile_name
                    use_case["FoundURIs"] = []
                    use_case["UseCaseId"] = _use_case_id_counter
                    _use_case_id_counter += 1

        # Build up required profile info
        if "RequiredProfiles" in self._raw:
            for profile in self._raw["RequiredProfiles"]:
                version = ".v" + self._raw["RequiredProfiles"][profile].get("MinVersion", "0.0.0").replace(".", "_") + "."
                self._required_profiles.append((profile, version))


    def get_filename(self):
        """
        Gets the filename of the profile
        
        Returns:
            The filename of the profile
        """
        return self._filename


    def get_required_profiles(self):
        """
        Gets the list of required profiles
        
        Returns:
            The list of tuples containing required profiles with min versions
        """
        return self._required_profiles


    def get_profile_name(self):
        """
        Gets the name of the profile
        
        Returns:
            The name of the profile
        """
        return self._profile_name


    def get_resource_requirements(self, sut, resource_type, uri, payload):
        """
        Gets the resource requirements for a specific resource type and URI
        
        Args:
            sut: The system under test
            resource_type: The type of resource
            uri: The URI of the resource
            payload: The payload of the resource
            
        Returns:
            The list of resource requirements
        """
        if resource_type not in self._raw.get("Resources", {}):
            # Resource not in the profile; no requirements
            return []

        # For each use case, see if there is a match
        resource_requirements = []
        for use_case in self._raw["Resources"][resource_type]["UseCases"]:
            # Check if the URI matches
            if not helper.uri_check(use_case.get("URIs"), uri):
                continue

            # Check if the use case is applicable based on its type
            # Need to skip the "default" use case we insert since they always apply
            is_default_use_case = use_case.get("IsDefault", False)
            if not is_default_use_case:
                use_case_type = use_case.get("UseCaseType", "Normal")
                if use_case_type == "Normal":
                    # Perform comparison checks like with other profile elements
                    result = helper.evaluate_comparison(sut, "/" + use_case.get("UseCaseKeyProperty", ""), use_case.get("UseCaseComparison", "Equal"), use_case.get("UseCaseKeyValues", []), {}, payload)
                    if result:
                        # Use case doesn't apply, skip it
                        continue
                elif use_case_type == "AbsentResource":
                    # Look for the Absent state
                    if payload.get("Status", {}).get("State") != "Absent":
                        # Resource is not absent, skip it
                        continue
                else:
                    # Other types are based on parent resources
                    # Loop on parent URIs until a match is found
                    if use_case_type == "ChassisType":
                        parent_resource = "Chassis"
                        parent_prop = "ChassisType"
                    elif use_case_type == "DriveProtocol":
                        parent_resource = "Drive"
                        parent_prop = "Protocol"
                    elif use_case_type == "MemoryType":
                        parent_resource = "Memory"
                        parent_prop = "MemoryType"
                    elif use_case_type == "PortProtocol":
                        parent_resource = "Port"
                        parent_prop = "Protocol"
                    elif use_case_type == "ProcessorType":
                        parent_resource = "Processor"
                        parent_prop = "ProcessorType"
                    else:
                        logger.critical("Unknown use case type: {}".format(use_case_type))
                        continue

                    # Navigate up the URI tree to find a matching parent resource
                    # Stop when we get to the service root
                    uri_split = uri.split("/")
                    match = False
                    while len(uri_split) >= 3:
                        del uri_split[-1]

                        # Get the parent URI and check its type
                        parent_uri = "/" + "/".join(uri_split)
                        parent_type, _, _ = sut.get_resource_type(parent_uri)
                        if parent_type == parent_resource:
                            match = True
                            break
                    if match is False:
                        # No matching parent resource type in the tree; skip this use case
                        continue

                    # Get the parent resource and check its property value
                    parent_payload = sut.get_resource_data(parent_uri)
                    result = helper.evaluate_comparison(sut, parent_prop, use_case.get("UseCaseComparison", "Equal"), use_case.get("UseCaseKeyValues", []), {}, parent_payload)
                    if result:
                        # Use case doesn't apply, skip it
                        continue

            # Add profile and use case to requirements
            if uri not in use_case["FoundURIs"]:
                use_case["FoundURIs"].append(uri)
            resource_requirements.append(use_case)

        return resource_requirements

    def get_all_use_cases(self):
        """
        Gets all use cases for this profile
        
        Returns:
            The list of all use cases
        """
        use_cases = []
        for resource in self._raw["Resources"]:
            for use_case in self._raw["Resources"][resource]["UseCases"]:
                use_cases.append(use_case)
        return use_cases


def load_profile(profile_dir, profile_filename):
    """
    Reads a Redfish Interoperability Profile from a JSON file located in
    profile_dir, caches it in _parsed_profiles, and recursively loads any
    profiles referenced by its "RequiredProfiles" statement; required
    profiles are expected to reside in the same directory as the profile
    that references them

    Args:
        profile_dir: The directory containing the profile to load
        profile_filename: The filename of the profile to load
    """
    profile_path = os.path.join(profile_dir, profile_filename)

    # Reuse an already-loaded copy if this exact file has been processed before
    # (also protects against circular RequiredProfiles references)
    for profile in _parsed_profiles:
        if profile.get_filename() == profile_filename:
            return

    try:
        with open(profile_path, "r") as file_pointer:
            profile_content = file_pointer.read()
    except Exception as err:
        logger.critical("Could not load profile '{}': {}".format(profile_path, err))
        raise

    try:
        profile_validator = jsonschema.Draft7Validator(profile_schema.profile_schema)
        profile_errors = sorted(profile_validator.iter_errors(json.loads(profile_content)), key=str)
    except Exception as err:
        logger.critical("Could not validate profile '{}': {}".format(profile_filename, err))
        raise

    if profile_errors:
        logger.critical("{} does not conform to the Redfish Profile schema".format(profile_filename))
        for error in profile_errors:
            logger.critical("  - {}".format(error.message))
        raise ValueError("Profile does not conform to the Redfish Profile schema")
    profile = RedfishProfile(profile_content, profile_filename)

    # Cache the profile before recursing so circular requirements terminate
    _parsed_profiles.append(profile)

    # Get a list of files from the profile directory
    profile_files = os.listdir(profile_dir)

    # Recursively load any profiles named in the "RequiredProfiles" statement
    # from the same directory as the referencing profile
    for required_profile in profile.get_required_profiles():
        # Find the "latest" version of the required profile
        # The file name suggested by the profile contains the min version, so we could have something newer
        # Note: do not take newer versions where the major version is different; major version changes introduce compatability issues
        cur_ver_str, cur_ver = helper.get_version(required_profile[1])
        for profile_file in profile_files:
            if profile_file.startswith(required_profile[0]) and profile_file.endswith(".json"):
                _, file_ver = helper.get_version(profile_file)
                if file_ver is not None and file_ver > cur_ver and file_ver[0] == cur_ver[0]:
                    cur_ver = file_ver

        # Use the latest version found
        filename = required_profile[0] + "." + cur_ver_str.replace(".", "_") + ".json"
        required_path = os.path.join(profile_dir, filename)
        if not os.path.isfile(required_path):
            logger.critical(
                "Required profile '{}' referenced by '{}' was not found in '{}'".format(
                    filename, profile.get_filename(), profile_dir
                )
            )
            raise FileNotFoundError("Required profile not found")
        load_profile(profile_dir, filename)

    return


def get_requirements(sut, resource_type, uri, payload):
    """
    Get the requirements for a specific resource type and URI from all loaded profiles.
    
    Args:
        sut: The system under test
        resource_type: The type of resource
        uri: The URI of the resource
        payload: The payload of the resource
        
    Returns:
        The list of resource requirements
    """
    resource_requirements = []
    for profile in _parsed_profiles:
        resource_reqs = profile.get_resource_requirements(sut, resource_type, uri, payload)
        resource_requirements.extend(resource_reqs)
    return resource_requirements


def get_all_use_cases():
    """
    Get all use cases from all loaded profiles.
    
    Returns:
        The list of all use cases
    """
    use_cases = []
    for profile in _parsed_profiles:
        profile_use_cases = profile.get_all_use_cases()
        use_cases.extend(profile_use_cases)
    return use_cases

def get_profile_name():
    """
    Get the name of the first loaded profile.
    
    Returns:
        The name of the first loaded profile
    """
    try:
        return _parsed_profiles[0].get_profile_name()
    except:
        return None
