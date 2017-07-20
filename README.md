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

You may install the prerequisites by running:

pip3 install -r requirements.txt

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

The Tool has an option to ignore SSL certificate check if certificate is not installed on the client system. The certificate check can be switched on or off using the below parameter of the config.ini file. By default the parameter is set to ‘Off’.  UseSSL determines whether or not the https protocol is used.  If it is `Off`, it will also disable certification.
[Options]
UseSSL = <<On / Off>>
CertificateCheck = <<On / Off>>

Other  attributes under the “[Options]” section have schema specific implementations as described below
LocalOnlyMode - (boolean) Only test properties against Schema placed in the root of MetadataFilePath.
ServiceMode - (boolean) Only test properties against Resources/Schema that exist on the Service
MetadataFilePath – (string) This attribute points to the location of the DMTF schema file location, populated by xml files
LogPath - (string) Path with which to generate logs in
Timeout - (integer) Interval of time before timing out
SchemaSuffix - (string) When searching for local hard drive schema, append this if unable to derive the expected xml from the service's metadata
Session_UserName & Session_Password – These attributes are used to create a session in addition to the default UserName/Password combination available under [SystemInformation] section. Leave these attributes blank if only Administrator credentials are to be used for session specific tests. (This option is currently unimplemented)

Once the above details are updated for the system under test, the Redfish Interop Validator can be triggered from a command prompt by typing the below command:

python3 RedfishInteropValidator.py <profile> -c config/config.ini

Where profile is the Interop Profile in question.  There is additionally a --schema option, which would allow to specify a schema to validate the profile itself against, to validate that it is in fact a properly formatted profile to Redfish specification.  

Alternatively, all of these options are available through the command line.  A configuration file overrides every option specified in the command line, such that -c should not be specified.  In order to review these options, please run the command:

python3 RedfishInteropValidator.py -h

In order to run without a configuration file, the option --ip must be specified.

python3 RedfishInteropValidator.py <profile> --ip host:port [...]

## Execution flow
* 1.	Redfish Interop Validator starts with the Service root Resource Schema by querying the service with the service root URI and getting all the device information, the resources supported and their links. Once the response of the Service root query is verified against a given profile (given the profile contains specifications for ServiceRoot), the tool traverses through all the collections and Navigation properties returned by the service.
* 2.	For each navigation property/Collection of resource returned, it does following operations:
** i.	Reads all the Navigation/collection of resources from the respective resource collection schema file.
** ii.	Reads the schema file related to the particular resource, collects all the information about individual properties from the resource schema file and stores them into a dictionary
** iii.	Queries the service with the individual resource uri and validates all Resource returned by the service that are included in the profile specified to the tool.
* 3.	Step 2 repeats till all the URIs and resources are covered.
 
## Conformance Logs – Summary and Detailed Conformance Report
The Redfish Interop Validator generates an html report under the “logs” folder, named as  The report gives the detailed view of the individual properties checked, with the Pass/Fail/Skip/Warning status for each resource checked for conformance.

There is a verbose log file that may be referenced to diagnose tool or schema problems when the stdout print out is insufficient, located in logs/<ComplianceLog_MM_DD_YYYY_HHMMSS.html>
