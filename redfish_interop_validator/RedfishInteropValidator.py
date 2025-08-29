
# Copyright Notice:
# Copyright 2017-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

import os
import sys
import argparse
import logging
import json
import glob
from datetime import datetime
from urllib.parse import urlparse
from collections import Counter

import redfish_interop_validator.traverseInterop as traverseInterop
from redfish_interop_validator.profile import getProfiles, checkProfileAgainstSchema, hashProfile
from redfish_interop_validator.validateResource import validateSingleURI, validateURITree
from redfish_interop_validator.interop import testResultEnum
from redfish_interop_validator import logger

tool_version = '2.3.2'

def main(argslist=None, configfile=None):
    """Main command

    Args:
        argslist ([type], optional): List of arguments in the form of argv. Defaults to None.
    """
    argget = argparse.ArgumentParser(description='DMTF tool to test a service against a interop profile, version {}'.format(tool_version))

    # base tool
    argget.add_argument('-v', '--verbose', action='count', default=0, help='Verbosity of tool in stdout')
    argget.add_argument('-c', '--config', type=str, help='Configuration for this tool')

    # host info
    argget.add_argument('-i', '--ip', '--rhost', '-r', type=str, help='Address of host to test against, using http or https (example: https://123.45.6.7:8000)')
    argget.add_argument('-u', '--username', type=str, help='Username for Authentication')
    argget.add_argument('-p', '--password', type=str, help='Password for Authentication')
    argget.add_argument('--description', type=str, help='sysdescription for identifying logs, if none is given, draw from serviceroot')
    argget.add_argument('--forceauth', action='store_true', help='Force authentication on unsecure connections')
    argget.add_argument('--authtype', type=str, default='Basic', help='authorization type (None|Basic|Session|Token)')
    argget.add_argument('--token', type=str, help='bearer token for authtype Token')

    # validator options
    argget.add_argument('--payload', type=str, help='mode to validate payloads [Tree, Single, SingleFile, TreeFile] followed by resource/filepath', nargs=2)
    argget.add_argument('--logdir', type=str, default='./logs', help='directory for log files')
    argget.add_argument('--nooemcheck', action='store_false', dest='oemcheck', help='Don\'t check OEM items')
    argget.add_argument('--debugging', action="store_true", help='Output debug statements to text log, otherwise it only uses INFO')
    argget.add_argument('--required_profiles_dir', type=str, help='root directory for required profiles')
    argget.add_argument('--collectionlimit', type=str, default=['LogEntry', '20'], help='apply a limit to collections (format: RESOURCE1 COUNT1 RESOURCE2 COUNT2...)', nargs='+')

    # Config information unique to Interop Validator
    argget.add_argument('profile', type=str, default='sample.json', nargs='+', help='interop profile with which to validate service against')
    argget.add_argument('--schema', type=str, default=None, help='schema with which to validate interop profile against')
    argget.add_argument('--no_online_profiles', action='store_false', dest='online_profiles', help='Don\'t acquire profiles automatically from online')
    argget.add_argument('--warnrecommended', action='store_true', help='warn on recommended instead of pass')

    # todo: write patches
    argget.add_argument('--writecheck', action='store_true', help='(unimplemented) specify to allow WriteRequirement checks')

    args = argget.parse_args(argslist)

    if configfile is None:
        configfile = args.config

    start_tick = datetime.now()

    # Set logging file
    logger.set_standard_out(logger.Level.INFO - args.verbose if args.verbose < 3 else logger.Level.DEBUG)

    logpath = args.logdir

    if not os.path.isdir(logpath):
        os.makedirs(logpath)

    log_level = logger.Level.INFO if not args.debugging else logger.Level.DEBUG
    file_name = datetime.strftime(start_tick, os.path.join(logpath, "ConformanceLog_%m_%d_%Y_%H%M%S.txt"))

    logger.create_logging_file_handler(log_level, file_name)

    my_logger = logging.getLogger('rsv')
    my_logger.setLevel(logging.DEBUG)

    # Begin of log
    my_logger.info("Redfish Interop Validator, version {}".format(tool_version))
    my_logger.info("")

    if args.ip is None and configfile is None:
        my_logger.error('Configuration Error: No IP or Config Specified')
        argget.print_help()
        return 1, None, 'Configuration Incomplete'

    if configfile:
        from redfish_interop_validator.config import convert_config_to_args
        convert_config_to_args(args, configfile)
    else:
        from redfish_interop_validator.config import convert_args_to_config
        my_logger.info('Writing config file to log directory')
        configfilename = datetime.strftime(start_tick, os.path.join(logpath, "ConfigFile_%m_%d_%Y_%H%M%S.ini"))
        my_config = convert_args_to_config(args)
        with open(configfilename, 'w') as f:
            my_config.write(f)

    # Check if our URL is consistent
    scheme, netloc, _, _, _, _ = urlparse(args.ip)
    if scheme not in ['http', 'https']:
        my_logger.error('Configuration Error: IP is missing http or https')
        return 1, None, 'IP Incomplete'

    if netloc == '':
        my_logger.error('Configuration Error: IP is missing ip/host')
        return 1, None, 'IP Incomplete'

    if len(args.collectionlimit) % 2 != 0:
        my_logger.error('Configuration Error: Collection Limit requires two arguments per entry (ResourceType Count)')
        return 1, None, 'Collection Limit Incomplete'
    
    # Start printing config details, remove redundant/private info from print
    my_logger.info('Target URI: ' + args.ip)
    my_logger.info('\n'.join(
        ['{}: {}'.format(x, vars(args)[x] if x not in ['password'] else '******') for x in sorted(list(vars(args).keys() - set(['description']))) if vars(args)[x] not in ['', None]]))
    my_logger.info('Start time: ' + start_tick.strftime('%x - %X'))
    my_logger.info("")

    # Start our service
    try:
        currentService = traverseInterop.startService(vars(args))
    except Exception as ex:
        my_logger.debug('Exception caught while creating Service', exc_info=1)
        my_logger.error("Service Exception Error: Service could not be started: {}".format(ex))
        return 1, None, 'Service Exception'

    # Create a description of our service if there is none given
    if args.description is None and currentService.service_root:
        my_version = currentService.service_root.get('RedfishVersion', 'No Version')
        my_name = currentService.service_root.get('Name', '')
        my_uuid = currentService.service_root.get('UUID', 'No UUID')
        setattr(args, 'description', 'My Target System {}, version {}, {}'.format(my_name, my_version, my_uuid))

    my_logger.info('Description of service: {}\n'.format(args.description))

    # Interop Profile handling
    my_profiles = []
    my_paths = []
    success = True
    for filename in args.profile:
        with open(filename) as f:
            my_profiles.append((filename, json.loads(f.read())))
            my_paths.append(os.path.split(filename)[0])
    if args.schema is not None:
        with open(args.schema) as f:
            schema = json.loads(f.read())
            for name, profile in my_profiles:
                success = checkProfileAgainstSchema(profile, schema)
                if not success:
                    my_logger.info("Profile {} did not conform to the given schema...".format(name))
                    return 1, None, 'Profile Did Not Conform'

    if args.required_profiles_dir is not None:
        my_paths += glob.glob("{}/**/".format(args.required_profiles_dir), recursive=True)
    
    my_logger.info('Profile Hashes (run-time): ')
    for file_name, profile in my_profiles:
        profile_name = profile.get('ProfileName')
        profile_version = profile.get('ProfileVersion')
        my_logger.info('profile: {} {} {}, dict md5 hash: {}'.format(file_name, profile_name, profile_version, hashProfile(profile)))

    # Start main
    status_code = 1
    jsonData = None

    # Set our mode for reading new payloads
    if args.payload:
        pmode, ppath = args.payload
    else:
        pmode, ppath = 'Default', ''
    pmode = pmode.lower()

    if pmode not in ['tree', 'single', 'singlefile', 'treefile', 'default']:
        pmode = 'Default'
        my_logger.warning('Configuration Warning: PayloadMode or path invalid, using Default behavior')
    if 'file' in pmode:
        if ppath is not None and os.path.isfile(ppath):
            with open(ppath) as f:
                jsonData = json.load(f)
                f.close()
        else:
            my_logger.error('File not found for payload: {}'.format(ppath))
            return 1, None, 'File not found for payload: {}'.format(ppath)

    try:
        results = None
        processed_profiles = set()
        for file_name, profile in my_profiles:
            profile_name = profile.get('ProfileName')
            profile_version = profile.get('ProfileVersion')

            # Create a list of profiles, required imports, and show their hashes
            included_profiles, required_by_resource = getProfiles(profile, [os.getcwd()] + my_paths, online=args.online_profiles)

            all_profiles = [profile] + included_profiles

            my_logger.info('Profile Hashes (included by {}): '.format(file_name))
            for inner_profile in included_profiles:
                inner_profile_name = profile.get('ProfileName')
                inner_profile_version = profile.get('ProfileVersion')
                my_logger.info('\t{} {}, dict md5 hash: {}'.format(inner_profile_name, inner_profile_version, hashProfile(inner_profile)))

            my_logger.info('Profile Hashes (required by Resource): '.format(file_name))
            for inner_profile in required_by_resource:
                inner_profile_name = profile.get('ProfileName')
                inner_profile_version = profile.get('ProfileVersion')
                my_logger.info('\t{} {}, dict md5 hash: {}'.format(inner_profile_name, inner_profile_version, hashProfile(inner_profile)))

            for profile_to_process in all_profiles:
                processing_profile_name = profile_to_process.get('ProfileName')
                if processing_profile_name not in processed_profiles:
                    processed_profiles.add(profile_name)
                else:
                    my_logger.warning("Import Warning: Profile {} already processed".format({}))

                if 'single' in pmode:
                    success, new_results, _, _ = validateSingleURI(ppath, profile_to_process, 'Target', expectedJson=jsonData)
                elif 'tree' in pmode:
                    success, new_results, _, _ = validateURITree(ppath, profile_to_process, 'Target', expectedJson=jsonData)
                else:
                    success, new_results, _, _ = validateURITree('/redfish/v1/', profile_to_process, 'ServiceRoot', expectedJson=jsonData)
                if results is None:
                    results = new_results
                else:
                    for item_name, item in new_results.items():
                        for x in item['messages']:
                            x.name = profile_name + ' -- ' + x.name
                        if item_name in results:
                            results[item_name]['messages'].extend(item['messages'])
                        else:
                            results[item_name] = item
                        # resultsNew = {profileName+key: resultsNew[key] for key in resultsNew if key in results}
                        # results.update(resultsNew)
    except traverseInterop.AuthenticationError as e:
        # log authentication error and terminate program
        my_logger.error('{}'.format(e))
        return 1, None, 'Failed to authenticate with the service'

    # Close the connection
    try:
        currentService.close()
    except Exception as e:
        my_logger.error('Service Closure Error: Failed to log out of service; session may still be active ({})'.format(e))

    now_tick = datetime.now()
    my_logger.info('Elapsed time: {}'.format(str(now_tick - start_tick).rsplit('.', 1)[0]))

    final_counts = Counter()

    my_logger.info('\nListing any warnings and errors: ')

    for k, my_result in results.items():

        for msg in my_result['messages']:
            if msg.result in [testResultEnum.PASS]:
                final_counts['pass'] += 1
            if msg.result in [testResultEnum.NOT_TESTED]:
                final_counts['not_tested'] += 1

        warns = [x for x in my_result['records'] if x.levelno == logger.Level.WARN]
        errors = [x for x in my_result['records'] if x.levelno == logger.Level.ERROR]
        if len(warns + errors):
            my_logger.info(" ")
            my_logger.info(my_result['uri'])

            if len(warns):
                my_logger.info("Warnings")
                for record in warns:
                    final_counts[record.levelname.lower()] += 1
                    my_logger.log(record.levelno, ", ".join([x for x in [record.msg, record.result] if x])) 

            if len(errors):
                my_logger.info("Errors")
                for record in errors:
                    final_counts[record.levelname.lower()] += 1
                    my_logger.log(record.levelno, ", ".join([x for x in [record.msg, record.result] if x])) 

    import redfish_interop_validator.tohtml as tohtml

    html_str = tohtml.renderHtml(results, tool_version, start_tick, now_tick, currentService)

    lastResultsPage = datetime.strftime(start_tick, os.path.join(logpath, "InteropHtmlLog_%m_%d_%Y_%H%M%S.html"))

    tohtml.writeHtml(html_str, lastResultsPage)

    my_logger.info("\nResults Summary:")
    my_logger.info(", ".join([
        'Pass: {}'.format(final_counts['pass']),
        'Fail: {}'.format(final_counts['error']),
        'Warning: {}'.format(final_counts['warning']),
        'Not Tested: {}'.format(final_counts['nottested']),
        ]))

    success = final_counts['error'] == 0

    if not success:
        my_logger.error("Validation has failed: {} problems found".format(final_counts['error']))
    else:
        my_logger.info("Validation has succeeded.")
        status_code = 0
    
    return status_code, lastResultsPage, 'Validation done'


if __name__ == '__main__':
    status_code, lastResultsPage, exit_string = main()
    sys.exit(status_code)
