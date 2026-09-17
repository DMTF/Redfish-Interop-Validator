# Redfish Interop Validator

Copyright 2017-2026 DMTF.  All rights reserved.

[![License](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md)
[![PyPI](https://img.shields.io/pypi/v/redfish-interop-validator)](https://pypi.org/project/redfish-interop-validator/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat)](https://github.com/psf/black)
[![GitHub stars](https://img.shields.io/github/stars/DMTF/Redfish-Interop-Validator.svg?style=flat-square&label=github%20stars)](https://github.com/DMTF/Redfish-Interop-Validator)
[![GitHub Contributors](https://img.shields.io/github/contributors/DMTF/Redfish-Interop-Validator.svg?style=flat-square)](https://github.com/DMTF/Redfish-Interop-Validator/graphs/contributors)

## About

The Redfish Interop Validator is a Python3 tool for checking conformance of any Redfish service against Redfish interoperability profiles.
The tool is designed to be implementation-agnostic and is driven based on the Redfish specifications and profiles.
The scope of this tool is to only perform `GET` requests and verify their respective responses.

## Installation

From PyPI:

    pip install redfish_interop_validator

From GitHub:

    git clone https://github.com/DMTF/Redfish-Interop-Validator.git
    cd Redfish-Interop-Validator
    python setup.py sdist
    pip install dist/redfish_interop_validator-x.x.x.tar.gz

## Requirements

The Redfish Interop Validator requires Python3.

Required external packages:

```
colorama
jsonschema
openpyxl
redfish>=3.1.5
redfish_service_validator>=3.1.6
redfish_utilities>=3.4.8
```

If installing from GitHub, you may install the external packages by running:

    pip install -r requirements.txt

## Usage

```
usage: RedfishInteropValidator.py [-h] --user USER --password PASSWORD --rhost
                                  RHOST [--authtype {Basic,Session}]
                                  [--serv_http_proxy SERV_HTTP_PROXY]
                                  [--serv_https_proxy SERV_HTTPS_PROXY]
                                  [--logdir LOGDIR]
                                  [--payload PAYLOAD PAYLOAD]
                                  [--mockup MOCKUP]
                                  [--collectionlimit COLLECTIONLIMIT [COLLECTIONLIMIT ...]]
                                  [--nooemcheck] [--timeout TIMEOUT]
                                  [--debugging]
                                  profile

Validate Redfish services against profiles

positional arguments:
  profile               The Redfish profile to use to verify the service

options:
  -h, --help            show this help message and exit
  --user USER, -u USER, -user USER, --username USER
                        The username for authentication
  --password PASSWORD, -p PASSWORD
                        The password for authentication
  --rhost RHOST, -r RHOST, --ip RHOST, -i RHOST
                        The address of the Redfish service (with scheme)
  --authtype {Basic,Session}
                        The authorization type
  --serv_http_proxy SERV_HTTP_PROXY
                        The URL of the HTTP proxy for accessing the Redfish
                        service
  --serv_https_proxy SERV_HTTPS_PROXY
                        The URL of the HTTPS proxy for accessing the Redfish
                        service
  --logdir LOGDIR, --report-dir LOGDIR
                        The directory for generated report files; default:
                        'logs'
  --payload PAYLOAD PAYLOAD
                        Controls how much of the data model to test; option is
                        followed by the URI of the resource from which to
                        start
  --mockup MOCKUP       Path to directory containing mockups to override
                        responses from the service
  --collectionlimit COLLECTIONLIMIT [COLLECTIONLIMIT ...]
                        Applies a limit to testing resources in collections;
                        format: RESOURCE1 COUNT1 RESOURCE2 COUNT2 ...
  --nooemcheck          Don't check OEM items
  --timeout TIMEOUT, -timeout TIMEOUT
                        The timeout, in seconds, for the service to respond to
                        HTTP requests
  --debugging           Controls the verbosity of the debugging output; if not
                        specified only INFO and higher are logged
```

Example:

    rf_interop_validator -r https://192.168.1.100 -u USERNAME -p PASSWORD MyProfile.v1_0_0.json

The Redfish Interop Validator can be configured using either command-line arguments or a configuration file (config.ini).

### Payload Option

The `payload` option controls how much of the data model to test.
It takes two parameters as strings.

The first parameter specifies the scope for testing the service.
`Single` will test a specified resource.
`Tree` will test a specified resource and every subordinate URI discovered from it.

The second parameter specifies the URI of a resource to test.

Example: test `/redfish/v1/AccountService` and no other resources.

    `--payload Single /redfish/v1/AccountService`

Example: test `/redfish/v1/Systems/1` and all subordinate resources.

    `--payload Tree /redfish/v1/Systems/1`

### Mockup Option

The `mockup` option allows a tester to override responses from the service with a local mockup.
This allows a tester to debug and provide local fixes to resources without needing to rebuild the service under test.

This option takes a single string parameter.
The parameter specifies a local directory path to the `ServiceRoot` resource of a Redfish mockup tree.

The mockup files follow the Redfish mockup style, with the directory tree matching the URI segments under `/redfish/v1`, and with a single `index.json` file in each subdirectory as desired.
For examples of full mockups, see the Redfish Mockups Bundle (DSP2043) at https://www.dmtf.org/dsp/DSP2043.

Populate the mockup directory tree with `index.json` files wherever problematic resources need to be replaced.
Any replaced resource will report a warning in the report to indicate a workaround was used.

### Collection Limit Option

The `collectionlimit` option allows a tester to limit the number of collection members to test.
This is useful for large collections where testing every member does not provide enough additional test coverage to warrant the increased test time.

This option takes pairs of arguments where the first argument is the resource type to limit and the second argument is the maximum number of members to test.
Whenever a resource collection for the specified resource type is encountered during testing, the validator will only test up to the specified number of members.

If this option is not specified, the validator defaults to applying a limit of 20 members to LogEntry resources.

Example: do not test more than 10 `Sensor` resources and 20 `LogEntry` resources in a given collection

    `--collectionlimit Sensor 10 LogEntry 20`

## Test Results: Types of Errors and Warnings

This section details the various types of error or warning messages that the tool can produce as a result of the testing process.

### Required Resource Error

Indicates a resource that is required by the profile is not found in the service.

### Resource Capabilities Error

Indicates a resource does not support the required HTTP operations.
For example, if the profile requires a resource to support `POST`, but the resource does not support `POST`, this error will be reported.

### Read Requirement Error

Indicates a property from a resource does not meet the read requirement specified in the profile.
If the profile lists the property as mandatory, check if the service supports the property.

### Write Requirement Error

Indicates a property from a resource does not meet the write requirement specified in the profile.
If the profile lists the property as mandatory, check if the service supports the property.

### Supported Values Error

Indicates a property from a resource does not meet the minimum set of supported values specified in the profile for write operations.

### Min Count Error

Indicates a property from a resource does not meet the minimum array length specified in the profile.

### Comparison Error

Indicates a property from a resource does not meet the comparison requirement specified in the profile.
For example, if the profile requires a property to be equal to a specific value.

### Required Action Error

Indicates an action that is required by the profile is not found in the service.

### Required Action Info Error

Indicates an action that is required by the profile is found in the service, but does not contain an action info annotation.

### Mockup Used Warning

Indicates the resource that was tested used response data from a mockup that was provided by the `--mockup` argument.

### Resource Capabilities Warnings

Indicates a resource does not provide the HTTP `Allow` header in its response.

### Property Requirements Warning

Indicates a property from a resource is not a JSON object, but the profile is expecting it to be an object.
Check that the property is defined as a JSON object in schema.
If it is defined as a JSON object, the service's implementation of the property needs to be corrected.
If it is not defined as a JSON object, the profile is not defined properly for the property.

## Release Process

1. Go to the "Actions" page
2. Select the "Release and Publish" workflow
3. Click "Run workflow"
4. Fill out the form
5. Click "Run workflow"
