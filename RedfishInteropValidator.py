
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

import os
import sys
import re
from datetime import datetime
from collections import Counter, OrderedDict
import logging
import json
import traverseService as rst
import argparse
from io import StringIO

from commonProfile import getProfiles, checkProfileAgainstSchema, hashProfile
from traverseService import AuthenticationError
from tohtml import renderHtml, writeHtml
from metadata import setup_schema_pack
import commonInterop

rsvLogger = rst.getLogger()

VERBO_NUM = 15
logging.addLevelName(VERBO_NUM, "VERBO")

tool_version = '1.1.2'

def verboseout(self, message, *args, **kws):
    if self.isEnabledFor(VERBO_NUM):
        self._log(VERBO_NUM, message, args, **kws)
logging.Logger.verboseout = verboseout


def checkPayloadConformance(uri, decoded):
    """
    checks for @odata entries and their conformance
    These are not checked in the normal loop
    """
    messages = dict()
    success = True
    for key in [k for k in decoded if '@odata' in k]:
        paramPass = False
        if key == '@odata.id':
            paramPass = isinstance(decoded[key], str)
            paramPass = re.match(
                '(\/.*)+(#([a-zA-Z0-9_.-]*\.)+[a-zA-Z0-9_.-]*)?', decoded[key]) is not None
            pass
        elif key == '@odata.count':
            paramPass = isinstance(decoded[key], int)
            pass
        elif key == '@odata.context':
            paramPass = isinstance(decoded[key], str)
            paramPass = re.match(
                '(\/.*)+#([a-zA-Z0-9_.-]*\.)[a-zA-Z0-9_.-]*', decoded[key]) is not None
            pass
        elif key == '@odata.type':
            paramPass = isinstance(decoded[key], str)
            paramPass = re.match(
                '#([a-zA-Z0-9_.-]*\.)+[a-zA-Z0-9_.-]*', decoded[key]) is not None
            pass
        else:
            paramPass = True
        if not paramPass:
            rsvLogger.error(key + "@odata item not conformant: " + decoded[key])
            success = False
        messages[key] = (decoded[key], 'odata',
                         'Exists',
                         'PASS' if paramPass else 'FAIL')
    return success, messages


def setupLoggingCaptures():
    class WarnFilter(logging.Filter):
        def filter(self, rec):
            return rec.levelno == logging.WARN

    errorMessages = StringIO()
    warnMessages = StringIO()
    fmt = logging.Formatter('%(levelname)s - %(message)s')
    errh = logging.StreamHandler(errorMessages)
    errh.setLevel(logging.ERROR)
    errh.setFormatter(fmt)

    warnh = logging.StreamHandler(warnMessages)
    warnh.setLevel(logging.WARN)
    warnh.addFilter(WarnFilter())
    warnh.setFormatter(fmt)

    rsvLogger.addHandler(errh)
    rsvLogger.addHandler(warnh)

    yield

    rsvLogger.removeHandler(errh)
    rsvLogger.removeHandler(warnh)
    warnstrings = warnMessages.getvalue()
    warnMessages.close()
    errorstrings = errorMessages.getvalue()
    errorMessages.close()

    yield warnstrings, errorstrings


def validateSingleURI(URI, profile, uriName='', expectedType=None, expectedSchema=None, expectedJson=None, parent=None):
    """
    Validates a single URI that is given, returning its ResourceObject, counts and links
    """
    # rs-assertion: 9.4.1
    # Initial startup here
    # Initial startup here
    lc = setupLoggingCaptures()
    next(lc)

    # Start
    counts = Counter()
    results = OrderedDict()
    messages = []

    results[uriName] = {'uri': URI, 'success': False, 'counts': counts,
                        'messages': messages, 'errors': '', 'warns': '',
                        'rtime': '', 'context': '', 'fulltype': ''}

    # check for @odata mandatory stuff
    # check for version numbering problems
    # check id if its the same as URI
    # check @odata.context instead of local.  Realize that @odata is NOT a "property"

    # Attempt to get a list of properties
    if URI is None:
        if parent is not None:
            parentURI = parent.uri
        else:
            parentURI = '...'
        URI = parentURI + '...'
    if expectedJson is None:
        successGet, jsondata, status, rtime = rst.callResourceURI(URI)
    else:
        successGet, jsondata = True, expectedJson
    successPayload, odataMessages = checkPayloadConformance(URI, jsondata if successGet else {})

    if not successPayload:
        counts['failPayloadError'] += 1
        rsvLogger.error(str(URI) + ': payload error, @odata property non-conformant',)

    # Generate dictionary of property info
    try:
        propResourceObj = rst.createResourceObject(
            uriName, URI, expectedJson, expectedType, expectedSchema, parent)
        if not propResourceObj:
            counts['problemResource'] += 1
            results[uriName]['warns'], results[uriName]['errors'] = next(lc)
            return False, counts, results, None, None
    except AuthenticationError:
        raise  # re-raise exception
    except Exception:
        rsvLogger.exception("")
        counts['exceptionResource'] += 1
        results[uriName]['warns'], results[uriName]['errors'] = next(lc)
        return False, counts, results, None, None
    counts['passGet'] += 1

    # if URI was sampled, get the notation text from rst.uri_sample_map
    sample_string = rst.uri_sample_map.get(URI)
    sample_string = sample_string + ', ' if sample_string is not None else ''

    results[uriName]['uri'] = (str(URI))
    results[uriName]['samplemapped'] = (str(sample_string))
    results[uriName]['rtime'] = propResourceObj.rtime
    results[uriName]['context'] = propResourceObj.context
    results[uriName]['origin'] = propResourceObj.schemaObj.origin
    results[uriName]['fulltype'] = propResourceObj.typeobj.fulltype
    results[uriName]['success'] = True

    rsvLogger.info("\t URI {}, Type ({}), GET SUCCESS (time: {})".format(URI, propResourceObj.typeobj.stype, propResourceObj.rtime))

    uriName, SchemaFullType, jsondata = propResourceObj.name, propResourceObj.typeobj.fulltype, propResourceObj.jsondata
    SchemaNamespace, SchemaType = rst.getNamespace(
        SchemaFullType), rst.getType(SchemaFullType)

    objRes = profile.get('Resources')

    if SchemaType not in objRes:
        rsvLogger.debug(
                '\nNo Such Type in sample {} {}.{}, skipping'.format(URI, SchemaNamespace, SchemaType))
    else:
        rsvLogger.info("\n*** %s, %s", uriName, URI)
        rsvLogger.debug("\n*** %s, %s, %s", expectedType,
                        expectedSchema is not None, expectedJson is not None)
        objRes = objRes.get(SchemaType)
        rsvLogger.info(SchemaType)
        try:
            propMessages, propCounts = commonInterop.validateInteropResource(
                propResourceObj, objRes, jsondata)
            messages = messages.extend(propMessages)
            counts.update(propCounts)
        except Exception:
            rsvLogger.exception("Something went wrong")
            rsvLogger.error(
                'Could not finish validation check on this payload')
            counts['exceptionProfilePayload'] += 1
        rsvLogger.info('%s, %s\n', SchemaFullType, counts)

    # Get all links available
    results[uriName]['warns'], results[uriName]['errors'] = next(lc)

    rsvLogger.debug(propResourceObj.links)
    return True, counts, results, propResourceObj.links, propResourceObj


def validateURITree(URI, uriName, profile, expectedType=None, expectedSchema=None, expectedJson=None):
    """
    Validates a Tree of URIs, traversing from the first given
    """
    traverseLogger = rst.getLogger()

    allLinks = set()
    allLinks.add(URI)
    refLinks = list()

    # Resource level validation
    rcounts = Counter()
    rmessages = []
    rerror = StringIO()

    objRes = dict(profile.get('Resources'))

    # Validate top URI
    validateSuccess, counts, results, links, thisobj = \
        validateSingleURI(URI, profile, uriName, expectedType,
                          expectedSchema, expectedJson)

    # parent first, then child execution
    # do top level root first, then do each child root, then their children...
    # hold refs for last (less recursion)
    if validateSuccess:
        serviceVersion = profile.get("Protocol")
        if serviceVersion is not None:
            serviceVersion = serviceVersion.get('MinVersion', '1.0.0')
            msg, mpss = commonInterop.validateMinVersion(thisobj.jsondata.get("RedfishVersion", "0"), serviceVersion)
            rmessages.append(msg)

        currentLinks = [(l, links[l], thisobj) for l in links]
        # todo : churning a lot of links, causing possible slowdown even with set checks
        while len(currentLinks) > 0:
            newLinks = list()
            for linkName, link, parent in currentLinks:
                linkURI, autoExpand, linkType, linkSchema, innerJson = link

                if linkURI is None:
                    continue

                if linkURI.rstrip('/') in allLinks or linkType == 'Resource.Item':
                    continue

                if refLinks is not currentLinks and ('Links' in linkName.split('.') or 'RelatedItem' in linkName.split('.') or 'Redundancy' in linkName.split('.')):
                    refLinks.append((linkName, link, parent))
                    continue

                if autoExpand and linkType is not None:
                    linkSuccess, linkCounts, linkResults, innerLinks, linkobj = \
                        validateSingleURI(linkURI, profile, linkURI, linkType, linkSchema, innerJson, parent=parent)
                else:
                    linkSuccess, linkCounts, linkResults, innerLinks, linkobj = \
                        validateSingleURI(linkURI, profile, linkURI, linkType, linkSchema, parent=parent)

                allLinks.add(linkURI.rstrip('/'))

                if not linkSuccess:
                    continue

                innerLinksTuple = [(l, innerLinks[l], linkobj) for l in innerLinks]
                newLinks.extend(innerLinksTuple)
                results.update(linkResults)
                SchemaType = rst.getType(linkobj.typeobj.fulltype)

                # Check schema level for requirements
                if SchemaType in objRes:
                    traverseLogger.info("Checking service requirement for {}".format(SchemaType))
                    req = objRes[SchemaType].get("ReadRequirement", "Mandatory")
                    msg, pss = commonInterop.validateRequirement(req, None)
                    if pss and not objRes[SchemaType].get('mark', False):
                        rmessages.append(msg)
                        msg.name = SchemaType + '.' + msg.name
                        objRes[SchemaType]['mark'] = True

                    if "ConditionalRequirements" in objRes[SchemaType]:
                        innerList = objRes[SchemaType]["ConditionalRequirements"]
                        newList = list()
                        for condreq in innerList:
                            condtrue = commonInterop.checkConditionalRequirement(linkobj, condreq, (linkobj.jsondata, None), None)
                            if condtrue:
                                msg, cpss = commonInterop.validateRequirement(condreq.get("ReadRequirement", "Mandatory"), None)
                                if cpss:
                                    rmessages.append(msg)
                                    msg.name = SchemaType + '.Conditional.' + msg.name
                                else:
                                    newList.append(condreq)
                            else:
                                newList.append(condreq)
                        objRes[SchemaType]["ConditionalRequirements"] = newList

            if refLinks is not currentLinks and len(newLinks) == 0 and len(refLinks) > 0:
                currentLinks = refLinks
            else:
                currentLinks = newLinks

    # interop service level checks
    finalResults = OrderedDict()
    if URI not in ["/redfish/v1", "/redfish/v1/"]:
        resultEnum = commonInterop.sEnum.WARN
        traverseLogger.info("We are not validating root, warn only")
    else:
        resultEnum = commonInterop.sEnum.FAIL
    for left in objRes:
        if not objRes[left].get('mark', False):
            req = objRes[left].get("ReadRequirement", "Mandatory")
            rmessages.append(
                    commonInterop.msgInterop(left + '.ReadRequirement', req, 'Must Exist' if req == "Mandatory" else 'Any', 'DNE', resultEnum))
        if "ConditionalRequirements" in objRes[left]:
            innerList = objRes[left]["ConditionalRequirements"]
            for condreq in innerList:
                req = condreq.get("ReadRequirement", "Mandatory")
                rmessages.append(
                    commonInterop.msgInterop(left + '.Conditional.ReadRequirement', req, 'Must Exist' if req == "Mandatory" else 'Any', 'DNE', resultEnum))

    for item in rmessages:
        if item.success == commonInterop.sEnum.WARN:
            rcounts['warn'] += 1
        elif item.success == commonInterop.sEnum.PASS:
            rcounts['pass'] += 1
        elif item.success == commonInterop.sEnum.FAIL:
            rcounts['fail.{}'.format(item.name)] += 1

    finalResults['n/a'] = {'uri': "Service Level Requirements", 'success':rcounts.get('fail', 0) == 0,\
            'counts':rcounts,\
            'messages':rmessages, 'errors':rerror.getvalue(), 'warns': '',\
            'rtime':'', 'context':'', 'fulltype':''}
    print(len(allLinks))
    finalResults.update(results)
    rerror.close()

    return validateSuccess, counts, finalResults, refLinks, thisobj


#############################################################
#########          Script starts here              ##########
#############################################################


validatorconfig = {'payloadmode': 'Default', 'payloadfilepath': None, 'logpath': './logs', 'writecheck': False}

def main(arglist=None, direct_parser=None):
    """
    Main program
    """
    argget = argparse.ArgumentParser(description='tool for testing services against an interoperability profile, version {}'.format(tool_version))

    # config
    argget.add_argument('-c', '--config', type=str, help='config file')

    # tool
    argget.add_argument('--desc', type=str, default='No desc', help='sysdescription for identifying logs')
    argget.add_argument('--payload', type=str, help='mode to validate payloads [Tree, Single, SingleFile, TreeFile] followed by resource/filepath', nargs=2)
    argget.add_argument('-v', action='store_const', const=True, default=None, help='verbose log output to stdout (parameter-only)')
    argget.add_argument('--logdir', type=str, default='./logs', help='directory for log files')
    argget.add_argument('--debug_logging', action="store_const", const=logging.DEBUG, default=logging.INFO,
            help='Output debug statements to text log, otherwise it only uses INFO (parameter-only)')
    argget.add_argument('--verbose_checks', action="store_const", const=VERBO_NUM, default=logging.INFO,
            help='Show all checks in logging (parameter-only)')
    argget.add_argument('--nooemcheck', action='store_const', const=True, default=None, help='Don\'t check OEM items')

    # service
    argget.add_argument('-i', '--ip', type=str, help='ip to test on [host:port]')
    argget.add_argument('-u', '--user', type=str, help='user for basic auth')
    argget.add_argument('-p', '--passwd', type=str, help='pass for basic auth')
    argget.add_argument('--linklimit', type=str, help='Limit the amount of links in collections, formatted TypeName:## TypeName:## ..., default LogEntry:20 ', nargs='*')
    argget.add_argument('--sample', type=int, help='sample this number of members from large collections for validation; default is to validate all members')
    argget.add_argument('--timeout', type=int, help='requests timeout in seconds')
    argget.add_argument('--nochkcert', action='store_const', const=True, default=None, help='ignore check for certificate')
    argget.add_argument('--nossl', action='store_const', const=True, default=None, help='use http instead of https')
    argget.add_argument('--forceauth', action='store_const', const=True, default=None, help='force authentication on unsecure connections')
    argget.add_argument('--authtype', type=str, help='authorization type (None|Basic|Session|Token)')
    argget.add_argument('--localonly', action='store_const', const=True, default=None, help='only use locally stored schema on your harddrive')
    argget.add_argument('--preferonline', action='store_const', const=True, default=None, help='use online schema')
    argget.add_argument('--service', action='store_const', const=True, default=None, help='only use uris within the service')
    argget.add_argument('--ca_bundle', type=str, help='path to Certificate Authority bundle file or directory')
    argget.add_argument('--token', type=str, help='bearer token for authtype Token')
    argget.add_argument('--http_proxy', type=str, help='URL for the HTTP proxy')
    argget.add_argument('--https_proxy', type=str, help='URL for the HTTPS proxy')
    argget.add_argument('--cache', type=str, help='cache mode [Off, Fallback, Prefer] followed by directory to fallback or override problem service JSON payloads', nargs=2)
    argget.add_argument('--uri_check', action='store_const', const=True, default=None, help='Check for URI if schema supports it')
    argget.add_argument('--version_check', type=str, help='Change default tool configuration based on the version provided (default use target version)')

    # metadata
    argget.add_argument('--schemadir', type=str, help='directory for local schema files')
    argget.add_argument('--schema_pack', type=str, help='Deploy DMTF schema from zip distribution, for use with --localonly (Specify url or type "latest", overwrites current schema)')
    argget.add_argument('--suffix', type=str, help='suffix of local schema files (for version differences)')

    # Config information unique to Interop Validator
    argget.add_argument('profile', type=str, default='sample.json', help='interop profile with which to validate service against')
    argget.add_argument('--schema', type=str, default=None, help='schema with which to validate interop profile against')
    argget.add_argument('--warnrecommended', action='store_true', help='warn on recommended instead of pass')
    # todo: write patches
    argget.add_argument('--writecheck', action='store_true', help='(unimplemented) specify to allow WriteRequirement checks')

    args = argget.parse_args(arglist)

    # set up config
    rst.ch.setLevel(args.verbose_checks if not args.v else logging.DEBUG)
    if direct_parser is not None:
        try:
            cdict = rst.convertConfigParserToDict(direct_parser)
            config, default_list = rst.setConfig(cdict)
        except Exception as ex:
            rsvLogger.debug('Exception caught while parsing configuration', exc_info=1)
            rsvLogger.error('Unable to parse configuration: {}'.format(repr(ex)))
            return 1, None, 'Config Parser Exception'
    elif args.config is None and args.ip is None:
        rsvLogger.info('No ip or config specified.')
        argget.print_help()
        return 1, None, 'Config Incomplete'
    else:
        try:
            config, default_list = rst.setByArgparse(args)
        except Exception as ex:
            rsvLogger.debug('Exception caught while parsing configuration', exc_info=1)
            rsvLogger.error('Unable to parse configuration: {}'.format(repr(ex)))
            return 1, None, 'Config Exception'

    # Set interop config items
    config['WarnRecommended'] = rst.config.get('warnrecommended', args.warnrecommended)
    commonInterop.config['WarnRecommended'] = config['WarnRecommended']
    config['WriteCheck'] = rst.config.get('writecheck', args.writecheck)
    commonInterop.config['WriteCheck'] = config['WriteCheck']
    config['profile'] = args.profile
    config['schema'] = args.schema

    # Setup schema store
    if config['schema_pack'] is not None and config['schema_pack'] != '':
        httpprox = config['httpproxy']
        httpsprox = config['httpsproxy']
        proxies = {}
        proxies['http'] = httpprox if httpprox != "" else None
        proxies['https'] = httpsprox if httpsprox != "" else None
        setup_schema_pack(config['schema_pack'], config['metadatafilepath'], proxies, config['timeout'])

    # Logging config
    logpath = config['logpath']
    startTick = datetime.now()
    if not os.path.isdir(logpath):
        os.makedirs(logpath)
    fmt = logging.Formatter('%(levelname)s - %(message)s')
    fh = logging.FileHandler(datetime.strftime(startTick, os.path.join(logpath, "InteropLog_%m_%d_%Y_%H%M%S.txt")))
    fh.setLevel(min(args.debug_logging, args.verbose_checks))
    fh.setFormatter(fmt)
    rsvLogger.addHandler(fh)

    # Then start service
    rsvLogger.info("Redfish Interop Validator, version {}".format(tool_version))
    try:
        currentService = rst.startService(config, default_list)
    except Exception as ex:
        rsvLogger.debug('Exception caught while creating Service', exc_info=1)
        rsvLogger.error("Service could not be started: {}".format(ex))
        return 1, None, 'Service Exception'

    metadata = currentService.metadata
    sysDescription, ConfigURI = (config['systeminfo'], config['targetip'])

    # start printing
    rsvLogger.info('ConfigURI: ' + ConfigURI)
    rsvLogger.info('System Info: ' + sysDescription)
    rsvLogger.info('Profile:' + config['profile'])
    rsvLogger.info('\n'.join(
        ['{}: {}'.format(x, config[x]) for x in sorted(list(config.keys() - set(['systeminfo', 'targetip', 'password', 'description']))) if config[x] not in ['', None]]))
    rsvLogger.info('Start time: ' + startTick.strftime('%x - %X'))

    # Interop Profile handling
    profile = schema = None
    success = True
    with open(args.profile) as f:
        profile = json.loads(f.read())
        if args.schema is not None:
            with open(args.schema) as f:
                schema = json.loads(f.read())
                success = checkProfileAgainstSchema(profile, schema)
    if not success:
        rsvLogger.info("Profile did not conform to the given schema...")
        return 1

    # Combine profiles
    profiles = getProfiles(profile, './')

    rsvLogger.info('\nProfile Hashes: ')
    for profile in profiles:
        profileName = profile.get('ProfileName')
        rsvLogger.info('profile: {}, dict md5 hash: {}'.format(profileName, hashProfile(profile) ))

    # Start main
    status_code = 1
    jsonData = None
    if rst.config.get('payloadmode') not in ['Tree', 'Single', 'SingleFile', 'TreeFile', 'Default']:
        rst.config['payloadmode'] = 'Default'
        rsvLogger.error('PayloadMode or path invalid, using Default behavior')
    if 'File' in rst.config.get('payloadmode'):
        if rst.config.get('payloadfilepath') is not None and os.path.isfile(rst.config.get('payloadfilepath')):
            with open(rst.config.get('payloadfilepath')) as f:
                jsonData = json.load(f)
                f.close()
        else:
            rsvLogger.error('File not found {}'.format(rst.config.get('payloadfilepath')))
            return 1

    results = None
    for profile in profiles:
        profileName = profile.get('ProfileName')
        if 'Single' in rst.config.get('payloadmode'):
            success, counts, resultsNew, xlinks, topobj = validateSingleURI(rst.config.get('payloadfilepath'), profile, 'Target', expectedJson=jsonData)
        elif 'Tree' in rst.config.get('payloadmode'):
            success, counts, resultsNew, xlinks, topobj = validateURITree(rst.config.get('payloadfilepath'), 'Target', profile, expectedJson=jsonData)
        else:
            success, counts, resultsNew, xlinks, topobj = validateURITree('/redfish/v1', 'ServiceRoot', profile, expectedJson=jsonData)

        if results is None:
            results = resultsNew
        else:
            for item in resultsNew:
                innerCounts = results[item]['counts']
                innerCounts.update(resultsNew[item]['counts'])
                if item in results:
                    for x in resultsNew[item]['messages']:
                        x.name = profileName + ' -- ' + x.name
                    results[item]['messages'].extend(resultsNew[item]['messages'])
            #resultsNew = {profileName+key: resultsNew[key] for key in resultsNew if key in results}
            #results.update(resultsNew)

    finalCounts = Counter()
    nowTick = datetime.now()
    rsvLogger.info('Elapsed time: {}'.format(str(nowTick-startTick).rsplit('.', 1)[0]))

    finalCounts.update(metadata.get_counter())
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
                rsvLogger.error('{} {} errors in {}'.format(innerCounts[countType], countType, results[item]['uri']))
            innerCounts[countType] += 0
        error_messages_present = False
        if results[item]['errors'] is not None and len(results[item]['errors']) > 0:
            error_messages_present = True
        if results[item]['warns'] is not None and len(results[item]['warns']) > 0:
            innerCounts['warningPresent'] = 1
        if counters_all_pass and error_messages_present:
            innerCounts['failErrorPresent'] = 1

        finalCounts.update(results[item]['counts'])

    fails = 0
    for key in [key for key in finalCounts.keys()]:
        if finalCounts[key] == 0:
            del finalCounts[key]
            continue
        if any(x in key for x in ['problem', 'fail', 'bad', 'exception']):
            fails += finalCounts[key]

    html_str = renderHtml(results, finalCounts, tool_version, startTick, nowTick)

    lastResultsPage = datetime.strftime(startTick, os.path.join(logpath, "InteropHtmlLog%m_%d_%Y_%H%M%S.html"))

    writeHtml(html_str, lastResultsPage)

    success = success and not (fails > 0)
    rsvLogger.info(finalCounts)

    if not success:
        rsvLogger.info("Validation has failed: {} problems found".format(fails))
    else:
        rsvLogger.info("Validation has succeeded.")
        status_code = 0

    return status_code, lastResultsPage, 'Validation done'


if __name__ == '__main__':
    status_code, lastResultsPage, exit_string = main()
    sys.exit(status_code)
