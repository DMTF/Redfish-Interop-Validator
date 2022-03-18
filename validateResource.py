# Copyright Notice:
# Copyright 2016-2021 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Service-Validator/blob/master/LICENSE.md

import logging
from collections import Counter
from io import StringIO

import traverseInterop
import common.interop as interop
from common.redfish import getType, getNamespace

my_logger = logging.getLogger()
my_logger.setLevel(logging.DEBUG)
class WarnFilter(logging.Filter):
    def filter(self, rec):
        return rec.levelno == logging.WARN

fmt = logging.Formatter('%(levelname)s - %(message)s')


def create_logging_capture(this_logger):
    errorMessages = StringIO()
    warnMessages = StringIO()

    errh = logging.StreamHandler(errorMessages)
    errh.setLevel(logging.ERROR)
    errh.setFormatter(fmt)

    warnh = logging.StreamHandler(warnMessages)
    warnh.setLevel(logging.WARN)
    warnh.addFilter(WarnFilter())
    warnh.setFormatter(fmt)

    this_logger.addHandler(errh)
    this_logger.addHandler(warnh)

    return errh, warnh


def get_my_capture(this_logger, handler):
    this_logger.removeHandler(handler)
    strings = handler.stream.getvalue()
    handler.stream.close()
    return strings


def validateSingleURI(URI, profile, uriName='', expectedType=None, expectedSchema=None, expectedJson=None, parent=None):
    """
    Validates a single URI that is given, returning its ResourceObject, counts and links
    """
    # rs-assertion: 9.4.1
    # Initial startup here
    counts = Counter()
    results, messages = {}, []

    ehandler, whandler = create_logging_capture(my_logger)

    results[uriName] = {'uri': URI,
                        'success': False,
                        'counts': counts,
                        'messages': messages,
                        'errors': '',
                        'warns': '',
                        'rtime': '',
                        'context': '',
                        'fulltype': '',
                        'rcode': 0,
                        'payload': {}}

    # check for @odata mandatory stuff
    # check for version numbering problems
    # check id if its the same as URI
    # check @odata.context instead of local.  Realize that @odata is NOT a "property"

    # Attempt to get a list of properties
    if URI is None:
        if parent is not None:
            parentURI = parent.uri
        else:
            parentURI = 'MissingParent'
        URI = parentURI + '/Missing URI Link'
        my_logger.warning('Tool appears to be missing vital URI information, replacing URI w/: {}'.format(URI))
    # Generate dictionary of property info
    try:
        if expectedJson is None:
            success, jsondata, status, rtime = traverseInterop.callResourceURI(URI)
            results[uriName]['payload'] = jsondata
        else:
            results[uriName]['payload'] = expectedJson

        # # verify basic odata strings
        # if results[uriName]['payload'] is not None:
        #     successPayload, odataMessages = traverseInterop.ResourceObj.checkPayloadConformance(results[uriName]['payload'], URI)
        #     messages.extend(odataMessages)

        propResourceObj = traverseInterop.createResourceObject(
            uriName, URI, expectedJson, expectedType, expectedSchema, parent)
        if not propResourceObj:
            counts['problemResource'] += 1
            results[uriName]['warns'], results[uriName]['errors'] = get_my_capture(my_logger, whandler), get_my_capture(my_logger, ehandler)
            return False, counts, results, None, None
    except traverseInterop.AuthenticationError as e:
        raise  # re-raise exception
    except Exception as e:
        my_logger.debug('Exception caught while creating ResourceObj', exc_info=1)
        my_logger.error('Unable to gather property info for URI {}: {}'
                        .format(URI, repr(e)))
        counts['exceptionResource'] += 1
        results[uriName]['warns'], results[uriName]['errors'] = get_my_capture(my_logger, whandler), get_my_capture(my_logger, ehandler)
        return False, counts, results, None, None

    counts['passGet'] += 1

    # verify odata type
    objRes = profile.get('Resources')

    my_logger.log(logging.INFO - 1, "*** %s, %s", uriName, URI)
    uriName, SchemaFullType, jsondata = uriName, uriName, propResourceObj.jsondata
    SchemaType = getType(jsondata.get('@odata.type', 'NoType'))
    if SchemaType not in objRes:
        # my_logger.info('\nNo Such Type in sample {} {}, skipping'.format(URI, SchemaType))
        # Get all links available
        links = getURIsInProperty(jsondata, uriName)
        return True, counts, results, links, propResourceObj

    # my_logger.info("\n*** %s", URI)
    # my_logger.debug("\n*** %s, %s, %s", expectedType, expectedSchema is not None, expectedJson is not None)

    # verify odata_id properly resolves to its parent if holding fragment
    odata_id = propResourceObj.jsondata.get('@odata.id', '')
    if '#' in odata_id:
        if parent is not None:
            payload_resolve = traverseInterop.navigateJsonFragment(parent.jsondata, URI)
            if payload_resolve is None:
                my_logger.error('@odata.id of ReferenceableMember does not contain a valid JSON pointer for this payload: {}'.format(odata_id))
                counts['badOdataIdResolution'] += 1
            elif payload_resolve != propResourceObj.jsondata:
                my_logger.error('@odata.id of ReferenceableMember does not point to the correct object: {}'.format(odata_id))
                counts['badOdataIdResolution'] += 1
        else:
            my_logger.warning('No parent found with which to test @odata.id of ReferenceableMember')

    # if not successPayload:
    #     counts['failPayloadError'] += 1
    #     my_logger.error(str(URI) + ': payload error, @odata property non-conformant',)

    # if URI was sampled, get the notation text from traverseInterop.uri_sample_map
    sample_string = traverseInterop.uri_sample_map.get(URI)
    sample_string = sample_string + ', ' if sample_string is not None else ''

    results[uriName]['uri'] = (str(URI))
    results[uriName]['samplemapped'] = (str(sample_string))
    results[uriName]['rtime'] = propResourceObj.rtime
    results[uriName]['rcode'] = propResourceObj.status
    results[uriName]['payload'] = propResourceObj.jsondata
    results[uriName]['context'] = propResourceObj.context
    results[uriName]['fulltype'] = propResourceObj.typename
    results[uriName]['success'] = True

    my_logger.info('\n')
    my_logger.info("*** %s, %s", URI, SchemaType)
    my_logger.debug("*** %s, %s, %s", expectedType, expectedSchema is not None, expectedJson is not None)
    my_logger.info("\t Type (%s), GET SUCCESS (time: %s)", propResourceObj.typename, propResourceObj.rtime)
    objRes = objRes.get(SchemaType)
    try:
        propMessages, propCounts = interop.validateInteropResource(propResourceObj, objRes, jsondata)
        messages = messages.extend(propMessages)
        counts.update(propCounts)
        my_logger.info('{} of {} tests passed.'.format(counts['pass'] + counts['warn'], counts['totaltests']))
    except Exception:
        my_logger.exception("Something went wrong")
        my_logger.error(
            'Could not finish validation check on this payload')
        counts['exceptionProfilePayload'] += 1
    my_logger.info('%s, %s\n', SchemaFullType, counts)

    # Get all links available
    links = getURIsInProperty(propResourceObj.jsondata, uriName)

    results[uriName]['warns'], results[uriName]['errors'] = get_my_capture(my_logger, whandler), get_my_capture(my_logger, ehandler)

    pass_val = len(results[uriName]['errors']) == 0
    for key in counts:
        if any(x in key for x in ['problem', 'fail', 'bad', 'exception']):
            pass_val = False
            break
    my_logger.info("\t {}".format('PASS' if pass_val else' FAIL...'))

    return True, counts, results, links, propResourceObj

import re
urlCheck = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
allowable_annotations = ['@odata.id']

def getURIsInProperty(property, name='Root'):
    my_links = {}
    if isinstance(property, dict):
        for x, y in property.items():
            if '@' in x and x.lower() not in allowable_annotations:
                continue
            if isinstance(y, str) and x.lower() in ['@odata.id']:
                my_link = getURIfromOdata(y)
                if my_link: my_links[name] = my_link
            else:
                my_links.update(getURIsInProperty(y, "{}:{}".format(name, x)))
    if isinstance(property, list):
        for n, x in enumerate(property):
            my_links.update(getURIsInProperty(x, "{}#{}".format(name, n)))
    return my_links

def getURIfromOdata(property):
    if '.json' not in property[:-5].lower():
        if '/redfish/v1' in property or urlCheck.match(property):
            return property
    return None
            
def validateURITree(URI, profile, uriName, expectedType=None, expectedSchema=None, expectedJson=None, check_oem=True):
    """name
    Validates a Tree of URIs, traversing from the first given
    """
    allLinks = set()
    allLinks.add(URI)
    refLinks = list()

    # Resource level validation
    rcounts = Counter()
    rerror = StringIO()
    rmessages = []
    r_exists = {}

    resource_info = dict(profile.get('Resources'))

    # Validate top URI
    validateSuccess, counts, results, links, thisobj = \
        validateSingleURI(URI, profile, uriName, expectedType, expectedSchema, expectedJson)

    # parent first, then child execution
    # do top level root first, then do each child root, then their children...
    # hold refs for last (less recursion)
    if validateSuccess:
        serviceVersion = profile.get("Protocol")
        if serviceVersion is not None and uriName == 'ServiceRoot':
            serviceVersion = serviceVersion.get('MinVersion', '1.0.0')
            msg, m_success = interop.validateMinVersion(thisobj.jsondata.get("RedfishVersion", "0"), serviceVersion)
            rmessages.append(msg)

        currentLinks = [(l, links[l], thisobj) for l in links]
        # todo : churning a lot of links, causing possible slowdown even with set checks
        while len(currentLinks) > 0:
            newLinks = list()
            for linkName, link, parent in currentLinks:
                assert(isinstance(link, str))
                if link is None or link.rstrip('/') in allLinks:
                    continue
            
                if '#' in link:
                    # if link.rsplit('#', 1)[0] not in allLinks:
                    #     refLinks.append((linkName, link, parent))
                    continue

                if 'Oem' in linkName and not check_oem:
                    my_logger.info('Skipping Oem Link')
                    continue

                if refLinks is not currentLinks and ('Links' in linkName.split('.') or 'RelatedItem' in linkName.split('.') or 'Redundancy' in linkName.split('.')):
                    refLinks.append((linkName, link, parent))
                    continue

                # if autoExpand and linkType is not None:
                #     linkSuccess, linkCounts, linkResults, innerLinks, linkobj = \
                #         validateSingleURI(linkURI, profile, linkURI, linkType, linkSchema, innerJson, parent=parent)
                else:
                    linkSuccess, linkCounts, linkResults, innerLinks, linkobj = \
                        validateSingleURI(link, profile, linkName, parent=parent)

                allLinks.add(link.rstrip('/'))

                if not linkSuccess:
                    continue

                innerLinksTuple = [(l, innerLinks[l], linkobj) for l in innerLinks]
                newLinks.extend(innerLinksTuple)
                results.update(linkResults)
                SchemaType = getType(linkobj.jsondata.get('@odata.type', 'NoType'))

                r_exists[SchemaType] = True

            if refLinks is not currentLinks and len(newLinks) == 0 and len(refLinks) > 0:
                currentLinks = refLinks
            else:
                currentLinks = newLinks

    # interop service level checks
    finalResults = {}
    my_logger.info('Service Level Checks')
    if URI not in ["/redfish/v1", "/redfish/v1/"]:
        resultEnum = interop.sEnum.WARN
        my_logger.info("We are not validating root, warn only")
    else:
        resultEnum = interop.sEnum.FAIL

    # for item in resource_info:
    #     # thisobj does not exist if we didn't find the first resource
    #     if thisobj and item == getType(thisobj.typeobj.fulltype):
    #         continue

    #     exists = r_exists.get(item, False)

    #     if "ConditionalRequirements" in resource_info[item]:
    #         innerList = resource_info[item]["ConditionalRequirements"]
    #         for condreq in innerList:
    #             if interop.checkConditionalRequirementResourceLevel(r_exists, condreq, item):
    #                 my_logger.info(
    #                     'Service Conditional for {} applies'.format(item))
    #                 req = condreq.get("ReadRequirement", "Mandatory")
    #                 rmessages.append(
    #                     interop.msgInterop(item + '.Conditional.ReadRequirement',
    #                                              req, 'Must Exist' if req == "Mandatory" else 'Any', 'DNE' if not exists else 'Exists',
    #                                              resultEnum if not exists and req == "Mandatory" else interop.sEnum.PASS))
    #             else:
    #                 my_logger.info(
    #                     'Service Conditional for {} does not apply'.format(item))

    #     req = resource_info[item].get("ReadRequirement", "Mandatory")

    #     if not exists:
    #         rmessages.append(
    #             interop.msgInterop(item + '.ReadRequirement', req,
    #                                      'Must Exist' if req == "Mandatory" else 'Any', 'DNE',
    #                                      resultEnum if req == "Mandatory" else interop.sEnum.PASS))
    #     else:
    #         rmessages.append(
    #             interop.msgInterop(item + '.ReadRequirement', req,
    #                                      'Must Exist' if req == "Mandatory" else 'Any', 'Exists',
    #                                      interop.sEnum.PASS))

    for item in rmessages:
        if item.success == interop.sEnum.WARN:
            rcounts['warn'] += 1
        elif item.success == interop.sEnum.PASS:
            rcounts['pass'] += 1
        elif item.success == interop.sEnum.FAIL:
            rcounts['fail.{}'.format(item.name)] += 1

    finalResults['n/a'] = {'uri': "Service Level Requirements", 'success': rcounts.get('fail', 0) == 0,
                           'counts': rcounts,
                           'messages': rmessages, 'errors': rerror.getvalue(), 'warns': '',
                           'rtime': '', 'context': '', 'fulltype': ''}
    finalResults.update(results)
    rerror.close()

    return validateSuccess, counts, finalResults, refLinks, thisobj
