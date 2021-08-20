Copyright 2017-2020 DMTF. All rights reserved.

# Redfish Interop Validator

## About

The Redfish Interop Validator is a python3 tool that will validate a service based on an Interoperability profile given to the tool.  The purpose of the tool is to guarantee that a specific service is compatible with vendor systems or system tools based on a vendor's specification in a profile.

## Introduction

This tool is designed to accept a profile conformant to the schematics specified by the DMTF Redfish Profile schema, and run against any valid Redfish service for a given device.  It is not biased to any specific hardware, only dependent on the current Redfish specification.

## Pre-requisites

The Redfish Interop Validator is based on Python 3 and the client system is required to have the Python framework installed before the tool can be installed and executed on the system. Additionally, the following packages are required to be installed and accessible from the python environment:
* beautifulsoup4  - https://pypi.python.org/pypi/beautifulsoup4/ (must be >= 4.6.0)
* requests  - https://github.com/kennethreitz/requests (Documentation is available at http://docs.python-requests.org/)
* lxml - https://pypi.python.org/pypi/lxml
* jsonschema

You may install the prerequisites by running:

`pip3 install -r requirements.txt`

If you have a previous beautifulsoup4 installation, please use the following command:

`pip3 install beautifulsoup4 --upgrade`

There is no dependency based on Windows or Linux OS. The result logs are generated in HTML format and an appropriate browser (Chrome, Firefox, IE, etc.) is required to view the logs on the client system.

## Installation

Place the RedfishInteropValidator.py tool into the desired tool root directory.  Create the following subdirectories in the tool root directory: "config" and "logs".  Place the example config.ini file in the "config" directory.  The Interop Validator requires access to Redfish schema CSDL files.  The path for these files is specified in the config.ini file with 'MetadataFilePath' under [Options].  The file path should be created and all schema CSDL .xml files must be placed there.  Note - the schema files for the latest Redfish release can be found in the 'csdl' folder of DSP8010, which is available at https://www.dmtf.org/dsp/DSP8010.

## Execution Steps

The Redfish Interop Validator is designed to execute as a purely command line interface tool with no intermediate inputs expected during tool execution. However, the tool requires various inputs regarding system details, DMTF schema files etc. which are consumed by the tool during execution to generate the conformance report logs. Below are the step by step instructions on setting up the tool for execution on any identified Redfish device for conformance test:

Modify the config\example.ini file to enter the system details under below section

### [Tool]

Variable   | Type   | Definition
--         |--      |--
Version    | string | Internal config version (optional)
Copyright  | string | _DMTF_ copyright (optional)
verbose    | int    | level of verbosity (0-3) 

### [Interop]
Variable   | Type   | Definition
--         |--      |--
Profile    | string | name of the testing profile (mandatory)
Schema     | string | name of json schema to test profile against

### [Host]
Variable   | Type    | Definition
--         |--       |--
ip         | string  | Host of testing system, formatted as https:// ip : port (can use http as well)
username   | string  | Username for Basic authentication
password   | string  | Password for Basic authentication (removed from logs)
description| string  | Description of system being tested (optional)
forceauth  | boolean | Force authentication even on http servers
authtype   | string  | Authorization type (Basic | Session | Token | None)
token      | string  | Token string for Token authentication

### [Validator]
Variable        | Type    | Definition
--              |--       |--
payload         | string  | Option to test a specific payload or resource tree (see below)
logdir          | string  | Place to save logs and run configs
nooemcheck      | boolean | Whether to check Oem items on service
debugging       | boolean | Whether to print debug to log
schema_directory| string  | Where schema is located/saved on system

### Payload options
The payload option takes two parameters as "option uri"

(Single, SingleFile, Tree, TreeFile)
How to test the payload URI given.  Single tests will only give a report on a single resource, while Tree will report on every link from that resource

([Filename], [uri])

URI of the target payload, or filename of a local file.

### HTML Log

To convert a previous HTML log into a csv file, use the following command:

`python3 tohtml.py htmllogfile`

## Execution flow

* 1.	Redfish Interop Validator starts with the Service root Resource Schema by querying the service with the service root URI and getting all the device information, the resources supported and their links. Once the response of the Service root query is verified against a given profile (given the profile contains specifications for ServiceRoot), the tool traverses through all the collections and Navigation properties returned by the service.
* 2.	For each navigation property/Collection of resource returned, it does following operations:
** i.	Reads all the Navigation/collection of resources from the respective resource collection schema file.
** ii.	Reads the schema file related to the particular resource, collects all the information about individual properties from the resource schema file and stores them into a dictionary
** iii.	Queries the service with the individual resource uri and validates all Resource returned by the service that are included in the profile specified to the tool.
* 3.	Step 2 repeats till all the URIs and resources are covered.

Upon validation of a resource, the following types of tests may occur:
* **Unlike** the Service Validator, the program will not necessarily list and warn problematic Resources, it will expect those problems to be found with the Service Validator and are ignored in the process here.
* When a Resource is found, check if this resource exists in the Profile provided, otherwise ignore it and move on to the next available resources via its Links.
* With the Resource initiated, begin to validate itself and the Properties that exist in the Profile given to the program with the following possible tests:
  * MinVersion - Test the @odata.type/version of the Resource which is being tested, which must be GREATER than the given MinVersion in the profile
  * MinCount - Test based on the @odata.count annotation, determine the size of the a given Collection or List, which must be GREATER than this given MinCount in the profile
  * ReadRequirement - Test the existence of a Property or Resource, depending on whether it is Recommended or Mandatory (others unimplemented) in the profile
  * Members - Test a Resource's "Members" property, which includes MinCount test
  * MinSupportedValues - Test the enumerations of a particular Property, based on the annotation @odata.SupportedValues and the given in the profile
  * Writeable/WriteRequirement - Test if the Property is ReadWrite capable, depending on if it is required in the profile
  * Comparison - Test between an Enum Property's value and values in the Profile, with a particular set of comparisons available:
    * AnyOf, AllOf = compare if any or all of the given values exist in a List or single Enum
    * GreaterThan, LessThan, Equal, ... = compare based on common comparisons Less, Greater or Equal
    * Absent, Present =  compare if a property exist or does not
  * ConditionalRequirements - Perform some of the above tests above if one of the specified requirements are True:
    * Subordinate - Test if this Resource is a child/link of the type tree listed 
    * Comparison - Test if a Comparison is True to a certain value
  * ActionRequirements - Perform tests based on what Actions require, such as ReadRequirement, AllowableValues
  * Check whether a Property is at first able to be nulled or is mandatory, and pass based on its Requirement or Nullability
  * For collections, validate each property inside of itself, and expects a list rather than a single Property, otherwise validate normally:
 
## Conformance Logs - Summary and Detailed Conformance Report

The Redfish Interop Validator generates reports in the "logs" folder: a text version named "InteropLog_MM_DD_YYYY_HHMMSS.txt" and an html version named "InteropHtmlLog_MM_DD_YYYY_HHMMSS.html". The reports give the detailed view of the individual properties checked, with the Pass/Fail/Skip/Warning status for each resource checked for conformance.

There is a verbose log file that may be referenced to diagnose tool or schema problems when the stdout print out is insufficient, located in logs/ConformanceLog_MM_DD_YYYY_HHMMSS.html

## Release Process

1. Update `CHANGELOG.md` with the list of changes since the last release
2. Update the `tool_version` variable in `RedfishInteropValidator.py` to reflect the new tool version
3. Push changes to Github
4. Create a new release in Github
