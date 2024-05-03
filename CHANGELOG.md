# Change Log

## [2.2.2] - 2024-05-03
- Added support for testing 'ActionInfo' requirements
- Corrected comparison testing behavior when a property is not present to not produce false failures

## [2.2.1] - 2024-04-19
- Fixed use case checking to only report an error if zero resources are found that match a mandatory use case

## [2.2.0] - 2024-03-22
- Corrected 'WriteRequirement' checking to not produce errors when a property is marked as 'Recommended', but writes are not supported

## [2.1.9] - 2024-02-26
- Added property WriteRequirement checks based on the usage of the 'Allow' response header and the '@Redfish.WriteableProperties' term

## [2.1.8] - 2024-02-09
- Added 'collectionlimit' argument to limit the number of entries checked in a collection

## [2.1.7] - 2024-01-08
- Fixed crash condition if a 'LinkToResource' comparison is performed and the link is not present
- Changed results for 'Recommended' and 'IfImplemented' properties to show 'Not Tested' if the property is not present

## [2.1.6] - 2023-11-03
- Corrected ConditionalRequirements to test Comparison and Values inside of matching ConditionalRequirements

## [2.1.5] - 2023-10-27
- Refactored project to publish tool on PyPI

## [2.1.4] - 2023-07-20
- Added support for testing 'ReplacedProperty' and 'ReplacedByProperty' statements
- Added support for testing profiles with 'UseCases' statements

## [2.1.3] - 2023-04-27
- Corrected behavior with the 'nooemcheck' flag to skip over any resources found in the 'Oem' object
- Downgraded errors to warnings for resources not accessible during testing

## [2.1.2] - 2023-01-09
- Corrected usage of AnyOf and AllOf checks to be across all resources

## [2.1.1] - 2022-10-14
- Added resource-level requirement checking, including conditional requirements

## [2.1.0] - 2022-06-24
- Fixed the resource GET result when running multiple profiles

## [2.0.9] - 2022-06-17
- Fixed the conditional requirements on list properties

## [2.0.8] - 2022-05-22
- Made correction to conditional checks for nested properties

## [2.0.7] - 2022-05-13
- Added 'required_profiles_dir' argument to specify directory containing required profiles
- Minor enhancements to debug output

## [2.0.6] - 2022-03-25
- Added missing step to log out of the session when done testing
- Added support for finding required profiles when the profile under test is in a different directory than the tool

## [2.0.5] - 2022-03-18
- Corrected comparison checks with integer properties
- Corrected test_action unit test
- Updated logging calls to use non-deprecated methods

## [2.0.4] - 2022-03-04
- Corrected URI checking to act as a filter for whether or not to apply the requirements

## [2.0.3] - 2022-01-31
- Added support for JSON Pointer syntax in 'CompareProperty'

## [2.0.2] - 2022-01-10
- Fixed version number comparisons for when a version segment reaches two digits

## [2.0.1] - 2021-09-17
- Fixed console status reporting of whether or not errors were found

## [2.0.0] - 2021-08-30
- Significant changes to the CLI arguments with the tool to reduce complexity for users
- Removed need for scanning schema files for performing testing of a service

## [1.1.8] - 2021-06-18
- Corrected conditional requirements to properly account for all values specified

## [1.1.7] - 2020-03-21
- Resynched common validation code with the Service Validator

## [1.1.6] - 2020-03-13
- Added support for `IfPopulated` expressions
- Added support for `@Redfish.ActionInfo` on actions

## [1.1.5] - 2020-01-17
- Added htmlLogScraper.py to generate a CSV style report

## [1.1.4] - 2019-07-19
- Downgraded several messages not related to interop profile conformance to be informational
- Fixes to handling of conditional requirements to not produce false errors

## [1.1.3] - 2019-06-21
- Added support for new URIs requirement added to 1.1.0 of the profile specification
- Made fixes to the handling of the `CompareProperty` term
- Made fix to the handling of `IfImplemented` to not treat it as mandatory
- Made fix to tracking of Service Root requirements
- Made enhancements to debug log output

## [1.1.2] - 2019-05-31
- Updated schema pack to 2019.1

## [1.1.1] - 2019-05-10
- Made fixes to version comparison testing

## [1.1.0] - 2019-04-12
- Added missing @odata.context initialization for Message Registries

## [1.0.9] - 2019-02-08
- Updated schema pack to 2018.3
- Fixed handling of the Redfish.Revisions term

## [1.0.8] - 2018-10-19
- Fixed how single entry comparisons were performed

## [1.0.7] - 2018-09-21
- Various bug fixes
- Added tool versioning
- Added profile names and hashes to test output

## [1.0.6] - 2018-09-07
- More updates to leverage common code with the Redfish-Service-Validator tool

## [1.0.5] - 2018-08-17
- Refactored project to leverage common service traversal code used in the Redfish-Service-Validator tool

## [1.0.4] - 2018-07-06
- Added support for validating requirements described by profiles listed in "RequiredProfiles"

## [1.0.3] - 2018-04-13
- Added prevention of invalid properties from being checked further

## [1.0.2] - 2018-03-16
- Fixed usage of the Protocol property to allow for it to be missing in the profile
- Added checking for invalid properties in payloads

## [1.0.1] - 2018-03-02
- Change "comply" to "conform" in various output messages

## [1.0.0] - 2018-01-26
- Initial release; conformant with version 1.0.0 of DSP0272
