Copyright 2017 Distributed Management Task Force, Inc. All rights reserved.
# Redfish Interop Validator - Version 0.91

## About
The Redfish Interop Validator is a python3 tool that will validate a service based on an Interoperability profile given to the tool.  The purpose of the tool is to guarantee that a specific service is compatible with vendor systems or system tools based on a vendor's specification in a profile.

## Introduction
This tool is designed to accept a profile conformant to the schematics specified by the DMTF Redfish Profile schema, and run against any valid Redfish service for a given device.  It is not biased to any specific hardware, only dependent on the current Redfish specification.

## Pre-requisites
The Redfish Interop Validator is based on Python 3 and the client system is required to have the Python framework installed before the tool can be installed and executed on the system. Additionally, the following packages are required to be installed and accessible from the python environment:
* beautifulsoup4  - https://pypi.python.org/pypi/beautifulsoup4/4.5.3 (must be <= 4.5.3)
* requests  - https://github.com/kennethreitz/requests (Documentation is available at http://docs.python-requests.org/)
* lxml - https://pypi.python.org/pypi/lxml
* jsonschema

You may install the prerequisites by running:

pip3 install -r requirements.txt

If you have a previous beautifulsoup4 installation, please use the following command:

pip3 install beautifulsoup4 --upgrade

There is no dependency based on Windows or Linux OS. The result logs are generated in HTML format and an appropriate browser (Chrome, Firefox, IE, etc.) is required to view the logs on the client system.

## Installation
The RedfishInteropValidator.py into the desired tool root directory.  Create the following subdirectories in the tool root directory: "config", "logs", "SchemaFiles".  Place the example config.ini file in the "config" directory.  Place the CSDL Schema files to be used by the tool in the root of the schema directory, or the directory given in config.ini.

## Execution Steps
The Redfish Interop Validator is designed to execute as a purely command line interface tool with no intermediate inputs expected during tool execution. However, the tool requires various inputs regarding system details, DMTF schema files etc. which are consumed by the tool during execution to generate the conformance report logs. Below are the step by step instructions on setting up the tool for execution on any identified Redfish device for conformance test:

Modify the config\config.ini file to enter the system details under below section
[SystemInformation]
TargetIP = <<IPv4 address of the system under test>>
UserName = <<User ID of Administrator on the system>>
Password = <<Password of the Administrator>>
AuthType = <<Type of authorization for above credentials (None,Basic,Session)>>

The Tool has an option to ignore SSL certificate check if certificate is not installed on the client system. The certificate check can be switched on or off using the below parameter of the config.ini file. By default the parameter is set to ‘Off’.  UseSSL determines whether or not the https protocol is used.  If it is `Off`, it will also disable certification.
[Options]
UseSSL = <<On / Off>>
CertificateCheck = <<On / Off>>
CertificateBundle = 

Other  attributes under the “[Options]” section have schema specific implementations as described below
LocalOnlyMode - (boolean) Only test properties against Schema placed in the root of MetadataFilePath.
ServiceMode - (boolean) Only test properties against Resources/Schema that exist on the Service
MetadataFilePath – (string) This attribute points to the location of the DMTF schema file location, populated by xml files
LogPath - (string) Path with which to generate logs in
Timeout - (integer) Interval of time before timing out
SchemaSuffix - (string) When searching for local hard drive schema, append this if unable to derive the expected xml from the service's metadata
HttpProxy - Proxy for http gets (untested)
HttpsProxy - Proxy for https gets (untested)

Additional options are available for cached files and 
CacheMode = [Off, Prefer, Fallback] -- Options for using a cache, which will allow a user to override or fallback to a file on disk during a resource call on a service
CacheFilePath = Path to cache directory
PayloadMode = [Default, Tree, Single, TreeFile, SingleFile] -- Options for the target of validation, allowing to specify a file or specific URI and traversal behavior
PayloadFilePath = Path to URI/File

Once the above details are updated for the system under test, the Redfish Interop Validator can be triggered from a command prompt by typing the below command, with the option of verbosity:

python3 RedfishInteropValidator.py <profile> -c config/config.ini (-v)

Alternatively, all of these options are available through the command line. __A configuration file overrides every option specified in the command line, such that -c should not be specified.__  In order to review these options, please run the command:

python3 RedfishInteropValidator.py -h (-v)

In order to run without a configuration file, the option --ip must be specified.

python3 RedfishInteropValidator.py <profile> --ip host:port [...]

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
 
## Conformance Logs – Summary and Detailed Conformance Report
The Redfish Interop Validator generates an html report under the “logs” folder, named as  The report gives the detailed view of the individual properties checked, with the Pass/Fail/Skip/Warning status for each resource checked for conformance.

There is a verbose log file that may be referenced to diagnose tool or schema problems when the stdout print out is insufficient, located in logs/<ComplianceLog_MM_DD_YYYY_HHMMSS.html>
