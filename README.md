Copyright 2017-2020 DMTF. All rights reserved.

# Redfish Interop Validator

## About

The Redfish Interop Validator is a python3 tool that will validate a service based on an Interoperability profile given to the tool.  The purpose of the tool is to guarantee that a specific service is compatible with vendor systems or system tools based on a vendor's specification in a profile.

## Introduction

This tool is designed to accept a profile conformant to the schematics specified by the DMTF Redfish Profile schema, and run against any valid Redfish service for a given device.  It is not biased to any specific hardware, only dependent on the current Redfish specification.

## Installation

From PyPI:

    pip install redfish_interop_validator

From GitHub:

    git clone https://github.com/DMTF/Redfish-Interop-Validator.git
    cd Redfish-Interop-Validator
    python setup.py sdist
    pip install dist/redfish_interop_validator-x.x.x.tar.gz

## Requirements

External modules:

* beautifulsoup4  - https://pypi.python.org/pypi/beautifulsoup4
* requests  - https://github.com/kennethreitz/requests (Documentation is available at http://docs.python-requests.org/)
* lxml - https://pypi.python.org/pypi/lxml
* jsonschema - https://pypi.org/project/jsonschema

You may install the prerequisites by running:

    pip3 install -r requirements.txt

If you have a previous beautifulsoup4 installation, use the following command:

    pip3 install beautifulsoup4 --upgrade

There is no dependency based on Windows or Linux OS.
The result logs are generated in HTML format and an appropriate browser, such as Chrome, Firefox, or Edge, is required to view the logs on the client system.

## Execution Steps

The Redfish Interop Validator is designed to execute as a purely command line interface tool with no intermediate inputs expected during tool execution.  Below are the step by step instructions on setting up the tool for execution on any identified Redfish device for conformance test:

Modify the config\example.ini file to enter the system details under below section

### [Tool]

| Variable  | Type   | Definition |
| :---      | :---   | :---       |
| Version   | string | Internal config version (optional) |
| Copyright | string | _DMTF_ copyright (optional) |
| verbose   | int    | level of verbosity (0-3) |

### [Interop]

| Variable  | Type   | Definition |
| :---      | :---   | :---       |
| Profile   | string | name of the testing profile (mandatory) |
| Schema    | string | name of json schema to test profile against |

### [Host]

| Variable    | Type   | Definition |
| :---        | :---   | :---       |
| ip          | string  | Host of testing system, formatted as https:// ip : port (can use http as well) |
| username    | string  | Username for Basic authentication |
| password    | string  | Password for Basic authentication (removed from logs) |
| description | string  | Description of system being tested (optional) |
| forceauth   | boolean | Force authentication even on http servers |
| authtype    | string  | Authorization type (Basic | Session | Token | None) |
| token       | string  | Token string for Token authentication |

### [Validator]

| Variable              | Type   | Definition |
| :---                  | :---   | :---       |
| payload               | string  | Option to test a specific payload or resource tree (see below) |
| logdir                | string  | Place to save logs and run configs |
| oemcheck              | boolean | Whether to check Oem items on service |
| online_profiles       | boolean | Whether to download online profiles |
| debugging             | boolean | Whether to print debug to log |
| required_profiles_dir | string  | Option to set the root folder of required profiles |

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
** i.	Reads all the Navigation/collection of resources.
** ii.	Queries the service with the individual resource uri and validates all Resource returned by the service that are included in the profile specified to the tool.
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

There is a verbose log file that may be referenced to diagnose tool problems when the stdout print out is insufficient, located in logs/ConformanceLog_MM_DD_YYYY_HHMMSS.html

## Release Process

1. Go to the "Actions" page
2. Select the "Release and Publish" workflow
3. Click "Run workflow"
4. Fill out the form
5. Click "Run workflow"
