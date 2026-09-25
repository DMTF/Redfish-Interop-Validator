# Copyright Notice:
# Copyright 2017-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md

"""
System Under Test

File : system_under_test.py

Brief : This file contains the definitions for tracking data for the test
        system.
"""

import re
import time
import redfish
import redfish_utilities
from pathlib import Path

from redfish_interop_validator import helper
from redfish_interop_validator import logger
from redfish_interop_validator import profile
from redfish_interop_validator import validate


class SystemUnderTest(object):
    def __init__(
        self, rhost, username, password, timeout, authtype, http_proxy, https_proxy, mockup, collection_limits, no_oem
    ):
        """
        Constructor for new system under test

        Args:
            rhost: The address of the Redfish service (with scheme)
            username: The username for authentication
            password: The password for authentication
            timeout: The HTTP timeout limit
            authtype: The authorization type to use
            http_proxy: The HTTP proxy for accessing the service
            https_proxy: The HTTPS proxy for accessing the service
            mockup: The mockup directory
            collection_limits: Limits for validating members in a collection
            no_oem: Indicator to skip OEM extensions
        """
        self._rhost = rhost
        self._username = username
        proxies = None
        if http_proxy or https_proxy:
            proxies = {}
            if http_proxy:
                proxies["http"] = http_proxy
            if https_proxy:
                proxies["https"] = https_proxy
        self._redfish_obj = redfish.redfish_client(
            base_url=rhost, username=username, password=password, proxies=proxies, timeout=timeout, max_retry=3
        )
        self._redfish_obj.login(auth=authtype.lower())
        self._mockup_dir = mockup
        self._no_oem = no_oem
        self._service_root = self._redfish_obj.root_resp.dict
        self._total_counts = {validate.Result.PASS.name: 0, validate.Result.WARN.name: 0, validate.Result.FAIL.name: 0, validate.Result.SKIP.name: 0}
        self._error_classes = {}
        self._warning_classes = {}
        self._profile_under_test = None
        self._use_case_under_test = None
        self._use_case_id_under_test = None

        # Find the manager to populate service info
        self._product = None
        self._product = self._service_root.get("Product", "N/A")
        self._fw_version = None
        self._model = None
        self._manufacturer = None
        if "Managers" in self._service_root:
            try:
                manager_ids = redfish_utilities.get_manager_ids(self._redfish_obj)
                if len(manager_ids) > 0:
                    manager = redfish_utilities.get_manager(self._redfish_obj, manager_ids[0])
                    self._fw_version = manager.dict.get("FirmwareVersion", "N/A")
                    self._model = manager.dict.get("Model", "N/A")
                    self._manufacturer = manager.dict.get("Manufacturer", "N/A")
            except:
                pass

        # Set up the resource cache
        self._resources = {}
        self._annotation_uris = []
        self._collection_capabilities_uris = []
        self._service_resource_results = { "Results": {}, validate.Result.FAIL.name: 0, validate.Result.WARN.name: 0, validate.Result.PASS.name: 0, validate.Result.SKIP.name: 0 }
        self._global_value_checks = {}

        # Build collection limits
        self._collection_limits = {}
        for resource_type, limit in zip(collection_limits[::2], collection_limits[1::2]):
            try:
                limit = int(limit)
            except:
                continue
            self._collection_limits[resource_type] = limit

    @property
    def rhost(self):
        """
        Accesses the address of the Redfish service

        Returns:
            The address of the Redfish service
        """
        return self._rhost

    @property
    def username(self):
        """
        Accesses the username for authentication

        Returns:
            The username for authentication
        """
        return self._username

    @property
    def firmware_version(self):
        """
        Accesses the firmware version of the service

        Returns:
            The firmware version of the service
        """
        return self._fw_version

    @property
    def model(self):
        """
        Accesses the model of the service

        Returns:
            The model of the service
        """
        return self._model

    @property
    def product(self):
        """
        Accesses the product of the service

        Returns:
            The product of the service
        """
        return self._product

    @property
    def manufacturer(self):
        """
        Accesses the manufacturer of the service

        Returns:
            The manufacturer of the service
        """
        return self._manufacturer

    @property
    def session(self):
        """
        Accesses the Redfish session

        Returns:
            The Redfish client object
        """
        return self._redfish_obj

    @property
    def service_root(self):
        """
        Accesses the service root data

        Returns:
            The service root data as a dictionary
        """
        return self._service_root

    @property
    def no_oem(self):
        """
        Indicator to skip OEM extensions

        Returns:
            Boolean indicator to skip OEM extensions
        """
        return self._no_oem

    @property
    def pass_count(self):
        """
        Accesses the pass count

        Returns:
            The pass count
        """
        return self._total_counts[validate.Result.PASS.name]

    @property
    def warn_count(self):
        """
        Accesses the warning count

        Returns:
            The warning count
        """
        return self._total_counts[validate.Result.WARN.name]

    @property
    def fail_count(self):
        """
        Accesses the fail count

        Returns:
            The fail count
        """
        return self._total_counts[validate.Result.FAIL.name]

    @property
    def skip_count(self):
        """
        Accesses the skip count

        Returns:
            The skip count
        """
        return self._total_counts[validate.Result.SKIP.name]

    def logout(self):
        """
        Logs out of the Redfish service
        """
        try:
            self._redfish_obj.logout()
        except Exception:
            pass

    def is_uri_from_annotation(self, uri):
        """
        Checks if a URI was discovered from an annotation

        Args:
            uri: The URI to check

        Returns:
            A boolean indicating if the URI is from an annotation
        """
        return uri in self._annotation_uris

    def is_uri_from_collection_capabilities(self, uri):
        """
        Checks if a URI was discovered from the colleciton capabilities annotation

        Args:
            uri: The URI to check

        Returns:
            A boolean indicating if the URI is from a collection capabilities annotation
        """
        return uri in self._collection_capabilities_uris

    def get_resource(self, uri):
        """
        Gets a resource for a URI

        Args:
            uri: The URI to get

        Returns:
            An object containing resource information about the URI
        """
        # Check if we attempted this URI
        if uri in self._resources:
            return self._resources[uri]

        # Not cached; go read it
        logger.debug("Caching {}...".format(uri))
        self._resources[uri] = {
            "Response": None,
            "Validated": False,
            "Exception": None,
            "Results": {},
            "Counts": {
                validate.Result.PASS.name: 0,
                validate.Result.WARN.name: 0,
                validate.Result.FAIL.name: 0,
                validate.Result.SKIP.name: 0,
            },
            "Mockup": False,
            "StatusCode": None,
            "ResponseTime": None,
        }
        try:
            if self._mockup_dir:
                # If a mockup directory was given, see if the resource exists in it
                uri_dirs = [uri.rstrip("/"), uri.rstrip("/")]
                uri_dirs[1] = uri_dirs[1].replace("/redfish/v1", "")
                for directory in uri_dirs:
                    mockup_file = Path(self._mockup_dir + directory + "/index.json")
                    if mockup_file.is_file():
                        # Mockup found; use its contents
                        with open(mockup_file) as mockup_data:
                            logger.debug("Found mockup of {}...".format(uri))
                            mockup_resp = {"Status": 200, "Content": mockup_data.read()}
                            self._resources[uri]["Response"] = redfish.rest.v1.StaticRestResponse(**mockup_resp)
                            self._resources[uri]["Mockup"] = True
                            self._resources[uri]["StatusCode"] = 200
                            self._resources[uri]["ResponseTime"] = 0
                            return self._resources[uri]
            _t0 = time.time()
            self._resources[uri]["Response"] = self._redfish_obj.get(uri)
            self._resources[uri]["ResponseTime"] = round((time.time() - _t0) * 1000)  # ms
            self._resources[uri]["StatusCode"] = self._resources[uri]["Response"].status
            if self._resources[uri]["Response"].status != 200:
                logger.critical(
                    "Could not access {}; HTTP status: {}".format(uri, self._resources[uri]["Response"].status)
                )
        except Exception as err:
            self._resources[uri]["Exception"] = err
            logger.critical("Could not access {}; {}".format(uri, err))
        return self._resources[uri]

    def get_resource_data(self, uri):
        """
        Gets the JSON payload for a resource.

        Args:
            uri: The URI to get

        Returns:
            A dictionary containing the resource payload; an empty dictionary
            if the resource could not be read or parsed
        """
        resource = self.get_resource(uri)
        if resource["Response"] is None:
            return {}

        try:
            return resource["Response"].dict
        except Exception:
            return {}

    def get_allow_header(self, uri):
        """
        Gets the Allow header for a resource

        Args:
            uri: The URI to get

        Returns:
            A string containing the Allow header
        """
        self.get_resource(uri)
        if uri not in self._resources:
            return None
        if self._resources[uri]["Response"] is None:
            return None
        if self._resources[uri]["Mockup"]:
            return None
        return self._resources[uri]["Response"].getheader("Allow")

    def get_resource_type(self, uri):
        """
        Gets the resource type for a resource

        Args:
            uri: The URI to get

        Returns:
            A string containing the resource type
            A string containing the resource version in the form 'vX.Y.Z'
            A tuple containing the resource version as (X, Y, Z)
        """
        resource = self.get_resource(uri)
        resource_type = None
        resource_version_str = None
        resource_version = None
        try:
            resource_type = resource["Response"].dict["@odata.type"].split(".")[-1]
            resource_version_str, resource_version = helper.get_version(resource["Response"].dict["@odata.type"])
        except:
            pass

        return resource_type, resource_version_str, resource_version

    def is_mockup(self, uri):
        """
        Determines if a URI came from a mockup

        Args:
            uri: The URI to get

        Returns:
            A boolean indicating if the response is from a mockup
        """
        if uri not in self._resources:
            return False
        return self._resources[uri]["Mockup"]

    def add_property_result(self, uri, prop, present, value, result):
        """
        Adds property test results to a resource

        Args:
            uri: The URI of the resource
            prop: The property path of the property tested
            present: Indicates if the property was found in the payload
            value: The value of the property that was tested
            result: A tuple containing the test results
        """
        if uri in self._resources:
            if prop in self._resources[uri]["Results"]:
                # Modify the existing results

                # Property already flagged; don't grow with PASS/SKIP messages
                if self._resources[uri]["Results"][prop]["Result"] in [validate.Result.WARN, validate.Result.FAIL]:
                    if result[0] in [validate.Result.PASS, validate.Result.SKIP]:
                        return

                # If the current result is SKIP or PASS, replace the current message with the new message
                if self._resources[uri]["Results"][prop]["Result"] in [validate.Result.SKIP, validate.Result.PASS]:
                    self._resources[uri]["Results"][prop]["Message"] = result[1]
                else:
                    # Append the result message to the existing list
                    self._resources[uri]["Results"][prop]["Message"] += "\n" + result[1]

                # Update the result if it's more severe than the current result
                if result[0] > self._resources[uri]["Results"][prop]["Result"]:
                    if self._resources[uri]["Validated"]:
                        # Need to unwind the results tally; this is done during global checks after we've marked a resource as validated
                        self._total_counts[self._resources[uri]["Results"][prop]["Result"].name] -= 1
                        self._resources[uri]["Counts"][self._resources[uri]["Results"][prop]["Result"].name] -= 1

                        # Adjust based on the new result
                        self._total_counts[result[0].name] += 1
                        self._resources[uri]["Counts"][result[0].name] += 1
                    self._resources[uri]["Results"][prop]["Result"] = result[0]
            else:
                # Add the results
                self._resources[uri]["Results"][prop] = {"Result": result[0], "Value": None, "Message": result[1]}

            # Append the profile info that dictates the requirement
            if self._profile_under_test is not None and self._use_case_under_test is not None:
                self._resources[uri]["Results"][prop]["Message"] += "; Profile: {}, Use Case: {}".format(self._profile_under_test, self._use_case_under_test)

            # Build up a test report-friendly value to uses
            if self._resources[uri]["Validated"]:
                combined_msg = "{} - {} ({}): {}".format(self._resources[uri]["Results"][prop]["Result"].name, prop, self._resources[uri]["Results"][prop]["Value"], self._resources[uri]["Results"][prop]["Message"])
            else:
                if prop != "":
                    if present:
                        if isinstance(value, dict):
                            if len(value) == 1 and "@odata.id" in value:
                                value_str = "[Link to: {}]".format(value["@odata.id"])
                            else:
                                value_str = "[Object]"
                        elif isinstance(value, list):
                            value_str = "[Array]"
                        elif isinstance(value, str) and len(value) == 0:
                            value_str = "[Empty String]"
                        elif value is None:
                            value_str = "[null]"
                        else:
                            value_str = str(value)
                    else:
                        value_str = "[Not Present]"
                    self._resources[uri]["Results"][prop]["Value"] = value_str
                    combined_msg = "{} - {} ({}): {}".format(result[0].name, prop, value_str, result[1])
                else:
                    self._resources[uri]["Results"][prop]["Value"] = "[Resource-level]"
                    combined_msg = "{} - {}".format(result[0].name, result[1])
            # Tally the results
            if result[0] == validate.Result.FAIL:
                logger.error(combined_msg)
            elif result[0] == validate.Result.WARN:
                logger.warning(combined_msg)
            else:
                logger.info(combined_msg)
            # Update the error bucket
            if result[0] == validate.Result.FAIL or result[0] == validate.Result.WARN:
                try:
                    error_type = result[1].split(":")[0]
                    dest = self._error_classes
                    if result[0] == validate.Result.WARN:
                        dest = self._warning_classes
                    if error_type not in dest:
                        dest[error_type] = 0
                    dest[error_type] += 1
                except:
                    logger.critical("Error message string '{}' is not formatted correctly".format(result[1]))

    def add_global_value_check(self, uri, prop, value, comparison, expected_values):
        """
        Adds a global value check result to the system under test

        Args:
            uri: The URI of the resource
            prop: The property path in the resource
            value: The actual value
            comparison: The comparison operator
            expected_values: The expected value
        """
        # Build the test name from the use case ID and the property path
        # The property path needs any numeric segments in the path cleaned since array numbers are not the same
        test_name = "{}_{}_{}".format(self._use_case_id_under_test, re.sub(r"\/\d+", "", prop), comparison)
        if test_name not in self._global_value_checks:
            self._global_value_checks[test_name] = { "Profile": self._profile_under_test, "UseCase": self._use_case_under_test, "Comparison": comparison, "ExpectedValues": expected_values, "FoundValues": [], "Properties": [] }
        # Cache the test data to follow-up on later
        self._global_value_checks[test_name]["Properties"].append({"URI": uri, "Property": prop})
        if not isinstance(value, list):
            value = [value]
        self._global_value_checks[test_name]["FoundValues"].extend(value)

    def set_resource_validated(self, uri, mockup):
        """
        Marks a resource as validated to indicate testing is complete

        Args:
            uri: The URI of the resource
            mockup: Indicates if the resource was populated from a mockup file
        """
        if uri in self._resources:
            self._resources[uri]["Validated"] = True

            # Tally the results
            for prop_result in self._resources[uri]["Results"].values():
                self._total_counts[prop_result["Result"].name] += 1
                self._resources[uri]["Counts"][prop_result["Result"].name] += 1

            # Mark a warning if the resource was populated from a mockup file and has results
            if mockup and len(self._resources[uri]["Results"]) != 0:
                self.add_property_result(
                    uri, "", False, None, (validate.Result.WARN, "Mockup Used Warning: Response was populated from a mockup file.")
                )
                self._total_counts[validate.Result.WARN.name] += 1
                self._resources[uri]["Counts"][validate.Result.WARN.name] += 1

            logger.log_print(
                "  - Pass: {}, Warn: {}, Fail: {}, Skip: {}".format(
                    self._resources[uri]["Counts"][validate.Result.PASS.name],
                    self._resources[uri]["Counts"][validate.Result.WARN.name],
                    self._resources[uri]["Counts"][validate.Result.FAIL.name],
                    self._resources[uri]["Counts"][validate.Result.SKIP.name],
                )
            )

    def find_uris(self, payload, uri_list, from_annotation, from_collection_capabilities):
        """
        Finds URIs in a payload

        Args:
            payload: The payload to scan
            uri_list: The list of URIs to update with any URIs found
            from_annotation: Indicates if we're stepping through an annotation that can contain URIs
            from_collection_capabilities: Indicates if we're stepping through a collection capabilities annotation
        """
        if isinstance(payload, dict):
            odata_type = payload.get("@odata.type")
            if isinstance(odata_type, str) and odata_type.startswith("#JsonSchemaFile."):
                # Don't go to URIs for JSON Schemas
                return
        for item in payload:
            if isinstance(payload, dict):
                # Skip OEM extensions if needed
                if item == "Oem" and self._no_oem:
                    continue

                # Skip OriginOfCondition
                if item == "OriginOfCondition":
                    continue

                # If the item is a reference, go to the resource
                if (
                    item == "@odata.id"
                    or item == "Uri"
                    or item == "Members@odata.nextLink"
                    or item == "@Redfish.ActionInfo"
                    or item == "DataSourceUri"
                    or item == "TargetComponentURI"
                ):
                    if isinstance(payload[item], str):
                        if payload[item].startswith("/") and "#" not in payload[item]:
                            uri_list.append(payload[item].rstrip("/"))
                            if from_annotation and payload[item] not in self._annotation_uris:
                                self._annotation_uris.append(payload[item])
                            if from_collection_capabilities and payload[item] not in self._collection_capabilities_uris:
                                self._collection_capabilities_uris.append(payload[item])

                # If the item is an object or array, scan one level deeper
                elif isinstance(payload[item], dict) or isinstance(payload[item], list):
                    if item == "CapabilitiesObject" or item == "SettingsObject":
                        from_annotation = True
                    if item == "CapabilitiesObject":
                        from_collection_capabilities = True
                    self.find_uris(payload[item], uri_list, from_annotation, from_collection_capabilities)

            # If the object is a list, see if the member needs to be scanned
            elif isinstance(payload, list):
                if isinstance(item, dict) or isinstance(item, list):
                    self.find_uris(item, uri_list, from_annotation, from_collection_capabilities)

    def validate(self, mode, start_uri, uri):
        """
        Performs validation of the service, recursively

        Args:
            mode: The traversal mode for the service
            start_uri: The starting URI for validation
            uri: The URI to test
        """
        # Get the URI
        resource = self.get_resource(uri)
        if resource["Validated"]:
            # Already tested
            return
        if self.is_uri_from_annotation(uri):
            # Skip annotation URIs
            return
        logger.log_print("Validating {}...".format(uri))

        # Check for exception cases that would fail the entire resource
        payload = validate.validate_response(resource)
        if payload is None:
            # Can't perform validation; stop here
            logger.critical("Cannot validate {}: no valid response".format(uri))
            self.set_resource_validated(uri, False)
            return

        # For resource collection, apply collection limits by removing members from the payload
        odata_type = payload.get("@odata.type")
        if isinstance(odata_type, str):
            resource_type = odata_type.split(".")[-1]
            match = re.match(r"^#(.+)Collection\..+Collection$", odata_type)
            if match and match[1] in self._collection_limits:
                if "Members" in payload and isinstance(payload["Members"], list):
                    payload["Members"] = payload["Members"][: self._collection_limits[match[1]]]
                payload.pop("Members@odata.nextLink", None)

            # Get the resource requirements from the profile
            resource_requirements = profile.get_requirements(self, resource_type, uri, payload)

            # Validate the resource against the found requirements
            if len(resource_requirements) == 0:
                logger.info("No requirements found for resource {}".format(uri))
            for use_case in resource_requirements:
                self._profile_under_test = use_case["ProfileName"]
                self._use_case_under_test = use_case["UseCaseTitle"]
                self._use_case_id_under_test = use_case["UseCaseId"]
                logger.info("Profile: {}, Use Case: {}".format(self._profile_under_test, self._use_case_under_test))

                # Resource-level
                validate.validate_resource(self, use_case, uri, payload)

                # Property requirements
                if "PropertyRequirements" in use_case:
                    validate.validate_properties(self, use_case["PropertyRequirements"], uri, payload, payload, "")

                # Action requirements
                if "ActionRequirements" in use_case:
                    validate.validate_actions(self, use_case["ActionRequirements"], uri, resource_type, payload)

                self._profile_under_test = None
                self._use_case_under_test = None
        else:
            logger.critical("Cannot determine the resource type for {}".format(uri))
        self.set_resource_validated(uri, resource["Mockup"])

        # Go through its contents and get the next URIs to test
        if mode == "Single":
            # Nothing else to do; don't scan deeper
            return
        next_uris = []
        payload.pop("@odata.id", None)  # Prevent potential retesting of the same URI
        self.find_uris(payload, next_uris, False, False)
        for next_uri in next_uris:
            if mode == "Tree" and not next_uri.startswith(start_uri):
                # In 'Tree' mode, skip URIs that are not subordinate to the starting URI
                continue
            self.validate(mode, start_uri, next_uri)

    def apply_global_checks(self):
        """
        Apply global checks to the system under test.
        """
        # Get all of the use cases to see if we meet the top-level requirements
        all_use_cases = profile.get_all_use_cases()
        for use_case in all_use_cases:
            read_requirement = use_case.get("ReadRequirement", "Mandatory")
            resource = use_case["Resource"]

            # Based on the read requirement and if any URIs matches, determine the result
            if len(use_case["FoundURIs"]) == 0:
                # No resources that match
                if read_requirement in ["Mandatory", "Supported"]:
                    # Mandatory resource not found
                    result = (validate.Result.FAIL, "Required Resource Error: Resource not found")
                elif read_requirement in ["Recommended", "IfImplemented", "IfPopulated"]:
                    # Optional resource not found
                    result = (validate.Result.SKIP, "Resource not found")
            else:
                # At least one match
                if read_requirement == "Excluded":
                    # Resource not allowed
                    result = (validate.Result.FAIL, "Disallowed Resource Error: Resource found but it is not allowed")
                else:
                    # Resource found
                    result = (validate.Result.PASS, "Resource found")

            # Build the result entry
            if resource not in self._service_resource_results["Results"]:
                # New result for the resource
                self._service_resource_results["Results"][resource] = { "Result": result[0], "Message": result[1] }
            else:
                # Existing result to update
                # If the current result is SKIP or PASS, replace the current message with the new message
                if self._service_resource_results["Results"][resource]["Result"] in [validate.Result.SKIP, validate.Result.PASS]:
                    self._service_resource_results["Results"][resource]["Message"] = result[1]
                else:
                    # Append the result message to the existing list
                    self._service_resource_results["Results"][resource]["Message"] += "\n" + result[1]

                # Update the result if it's more severe than the current result
                if result[0] > self._service_resource_results["Results"][resource]["Result"]:
                    self._service_resource_results["Results"][resource]["Result"] = result[0]

            # Append the profile info that dictates the requirement
            self._service_resource_results["Results"][resource]["Message"] += "; Profile: {}, Use Case: {}".format(use_case["ProfileName"], use_case["UseCaseTitle"])

            # Update the error category counts
            if result[0] == validate.Result.FAIL or result[0] == validate.Result.WARN:
                try:
                    error_type = result[1].split(":")[0]
                    dest = self._error_classes
                    if result[0] == validate.Result.WARN:
                        dest = self._warning_classes
                    if error_type not in dest:
                        dest[error_type] = 0
                    dest[error_type] += 1
                except:
                    logger.critical("Error message string '{}' is not formatted correctly".format(result[1]))

        # Update the total tallies for anything found
        for resource_result in self._service_resource_results["Results"].values():
            self._service_resource_results[resource_result["Result"].name] += 1
            self._total_counts[resource_result["Result"].name] += 1

        # Check property value requirements that span all resources
        for test in self._global_value_checks.values():
            result = None
            if test["Comparison"] == "AnyOf":
                # Just needs one value found
                match_found = False
                for value in test["ExpectedValues"]:
                    if value in test["FoundValues"]:
                        match_found = True
                        break
                if not match_found:
                    result = "Comparison Error: The property, across all instances in the service, does not contain one of the required values: {}".format(", ".join(test["ExpectedValues"]))
                    pass
            elif test["Comparison"] == "AllOf":
                # All values must be found
                for value in test["ExpectedValues"]:
                    if value not in test["FoundValues"]:
                        result = "Comparison Error: The property, across all instances in the service, does not contain all of the required values: {}".format(", ".join(test["ExpectedValues"]))
                        break
            elif test["Comparison"] == "ReadSupport":
                # At least one instance of the resource must have the property
                if True not in test["FoundValues"]:
                    result = "Read Requirement Error: The property is not present on any instances of the resource"
            else:
                # At least one instance of the resource must be writable
                # 'None' indicates we can't test, so we cannot fault the implementation if at least one instance is unknown
                if True not in test["FoundValues"] and None not in test["FoundValues"]:
                    result = "Write Requirement Property Error: The property is not writable on any instances of the resource"

            # Log failures if needed
            if result is not None:
                self._profile_under_test = test["Profile"]
                self._use_case_under_test = test["UseCase"]
                for prop in test["Properties"]:
                    self.add_property_result(prop["URI"], prop["Property"], True, None, (validate.Result.FAIL, result))
                self._profile_under_test = None
                self._use_case_under_test = None

        return
