
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

import os
import sys
import argparse
import logging
import json
from datetime import datetime

tool_version = '2.0.3'

my_logger = logging.getLogger()
my_logger.setLevel(logging.DEBUG)
standard_out = logging.StreamHandler(sys.stdout)
standard_out.setLevel(logging.INFO)
my_logger.addHandler(standard_out)

logging.addLevelName(logging.INFO - 1, "VERBOSE1")
logging.addLevelName(logging.INFO - 2, "VERBOSE2")

#####################################################
#          Script starts here              ##########
#####################################################

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
    argget.add_argument('-i', '--ip', type=str, help='Address of host to test against, using http or https (example: https://123.45.6.7:8000)')
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

    startTick = datetime.now()

    # set logging file
    standard_out.setLevel(logging.INFO - args.verbose if args.verbose < 3 else logging.DEBUG)

    logpath = args.logdir

    if not os.path.isdir(logpath):
        os.makedirs(logpath)

    fmt = logging.Formatter('%(levelname)s - %(message)s')
    file_handler = logging.FileHandler(datetime.strftime(startTick, os.path.join(logpath, "InteropLog_%m_%d_%Y_%H%M%S.txt")))
    file_handler.setLevel(min(logging.INFO if not args.debugging else logging.DEBUG, standard_out.level))
    file_handler.setFormatter(fmt)
    my_logger.addHandler(file_handler)

    my_logger.info("Redfish Interop Validator, version {}".format(tool_version))
    my_logger.info("")

    if args.ip is None and configfile is None:
        my_logger.error('No IP or Config Specified')
        argget.print_help()
        return 1, None, 'Configuration Incomplete'

    if configfile:
        from common.config import convert_config_to_args
        convert_config_to_args(args, configfile)
    else:
        from common.config import convert_args_to_config
        my_logger.info('Writing config file to log directory')
        configfilename = datetime.strftime(startTick, os.path.join(logpath, "ConfigFile_%m_%d_%Y_%H%M%S.ini"))
        my_config = convert_args_to_config(args)
        with open(configfilename, 'w') as f:
            my_config.write(f)

    from urllib.parse import urlparse, urlunparse
    scheme, netloc, _, _, _, _ = urlparse(args.ip)
    if scheme not in ['http', 'https']:
        my_logger.error('IP is missing http or https')
        return 1, None, 'IP Incomplete'

    if netloc == '':
        my_logger.error('IP is missing ip/host')
        return 1, None, 'IP Incomplete'

    # start printing config details, remove redundant/private info from print
    my_logger.info('Target URI: ' + args.ip)
    my_logger.info('\n'.join(
        ['{}: {}'.format(x, vars(args)[x] if x not in ['password'] else '******') for x in sorted(list(vars(args).keys() - set(['description']))) if vars(args)[x] not in ['', None]]))
    my_logger.info('Start time: ' + startTick.strftime('%x - %X'))
    my_logger.info("")
    
    import traverseInterop
    try:
        currentService = traverseInterop.startService(vars(args))
    except Exception as ex:
        my_logger.debug('Exception caught while creating Service', exc_info=1)
        my_logger.error("Service could not be started: {}".format(ex))
        return 1, None, 'Service Exception'
    
    if args.description is None and currentService.service_root:
        my_version = currentService.service_root.get('RedfishVersion', 'No Version')
        my_name = currentService.service_root.get('Name', '')
        my_uuid = currentService.service_root.get('UUID', 'No UUID')
        setattr(args, 'description', 'My Target System {}, version {}, {}'.format(my_name, my_version, my_uuid))

    my_logger.info('Description of service: {}'.format(args.description))

    # Interop Profile handling
    from common.profile import getProfiles, checkProfileAgainstSchema, hashProfile

    my_profiles = []
    success = True
    for filename in args.profile:
        with open(filename) as f:
            my_profiles.append((filename, json.loads(f.read())))
    if args.schema is not None:
        with open(args.schema) as f:
            schema = json.loads(f.read())
            for name, profile in my_profiles:
                success = checkProfileAgainstSchema(profile, schema)
                if not success:
                    my_logger.info("Profile {} did not conform to the given schema...".format(name))
                    return 1, None, 'Profile Did Not Conform'

    # Combine profiles
    all_profiles = []
    for name, profile in my_profiles:
        all_profiles.extend(getProfiles(profile, './', online=args.online_profiles))

    my_logger.info('\nProfile Hashes: ')
    for profile in all_profiles:
        profileName = profile.get('ProfileName')
        my_logger.info('profile: {}, dict md5 hash: {}'.format(profileName, hashProfile(profile)))

    # Start main
    status_code = 1
    jsonData = None

    if args.payload:
        pmode, ppath = args.payload
    else:
        pmode, ppath = 'Default', ''
    pmode = pmode.lower()

    if pmode not in ['tree', 'single', 'singlefile', 'treefile', 'default']:
        pmode = 'Default'
        my_logger.warn('PayloadMode or path invalid, using Default behavior')
    if 'file' in pmode:
        if ppath is not None and os.path.isfile(ppath):
            with open(ppath) as f:
                jsonData = json.load(f)
                f.close()
        else:
            my_logger.error('File not found for payload: {}'.format(ppath))
            return 1, None, 'File not found for payload: {}'.format(ppath)
    try:
        from validateResource import validateSingleURI, validateURITree
        results = None
        for profile in all_profiles:
            if 'single' in pmode:
                success, _, resultsNew, _, _ = validateSingleURI(ppath, profile, 'Target', expectedJson=jsonData)
            elif 'tree' in pmode:
                success, _, resultsNew, _, _ = validateURITree(ppath, profile, 'Target', expectedJson=jsonData, check_oem=args.oemcheck)
            else:
                success, _, resultsNew, _, _ = validateURITree('/redfish/v1/', profile, 'ServiceRoot', expectedJson=jsonData, check_oem=args.oemcheck)
            profileName = profile.get('ProfileName')
            if results is None:
                results = resultsNew
            else:
                for item in resultsNew:
                    for x in resultsNew[item]['messages']:
                        x.name = profileName + ' -- ' + x.name
                    if item in results:
                        innerCounts = results[item]['counts']
                        innerCounts.update(resultsNew[item]['counts'])
                        results[item]['messages'].extend(resultsNew[item]['messages'])
                    else:
                        results[item] = resultsNew[item]
                    # resultsNew = {profileName+key: resultsNew[key] for key in resultsNew if key in results}
                    # results.update(resultsNew)
    except traverseInterop.AuthenticationError as e:
        # log authentication error and terminate program
        my_logger.error('{}'.format(e))
        return 1, None, 'Failed to authenticate with the service'



    from collections import Counter
    finalCounts = Counter()
    nowTick = datetime.now()
    my_logger.info('Elapsed time: {}'.format(str(nowTick - startTick).rsplit('.', 1)[0]))

    for item in results:
        innerCounts = results[item]['counts']

        # detect if there are error messages for this resource, but no failure counts; if so, add one to the innerCounts
        counters_all_pass = True
        for countType in sorted(innerCounts.keys()):
            if innerCounts.get(countType) == 0:
                continue
            if any(x in countType for x in ['problem', 'fail', 'bad', 'exception']):
                counters_all_pass = False
            if 'fail' in countType or 'exception' in countType:
                my_logger.error('{} {} errors in {}'.format(innerCounts[countType], countType, results[item]['uri']))
            innerCounts[countType] += 0
        error_messages_present = False
        if results[item]['errors'] is not None and len(results[item]['errors']) > 0:
            error_messages_present = True
        if results[item]['warns'] is not None and len(results[item]['warns']) > 0:
            innerCounts['warningPresent'] = 1
        if counters_all_pass and error_messages_present:
            innerCounts['failErrorPresent'] = 1

        finalCounts.update(results[item]['counts'])

    import tohtml

    fails = 0
    for key in [key for key in finalCounts.keys()]:
        if finalCounts[key] == 0:
            del finalCounts[key]
            continue
        if any(x in key for x in ['problem', 'fail', 'bad', 'exception']):
            fails += finalCounts[key]

    html_str = tohtml.renderHtml(results, finalCounts, tool_version, startTick, nowTick, currentService.config)

    lastResultsPage = datetime.strftime(startTick, os.path.join(logpath, "InteropHtmlLog_%m_%d_%Y_%H%M%S.html"))

    tohtml.writeHtml(html_str, lastResultsPage)

    success = success and not (fails > 0)
    my_logger.info("\n".join('{}: {}   '.format(x, y) for x, y in sorted(finalCounts.items())))

    # dump cache info to debug log
    my_logger.debug('callResourceURI() -> {}'.format(currentService.callResourceURI.cache_info()))

    if not success:
        my_logger.error("Validation has failed: {} problems found".format(fails))
    else:
        my_logger.info("Validation has succeeded.")
        status_code = 0

    return status_code, lastResultsPage, 'Validation done'


if __name__ == '__main__':
    status_code, lastResultsPage, exit_string = main()
    sys.exit(status_code)
