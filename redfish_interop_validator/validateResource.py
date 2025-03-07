# Copyright Notice:
# Copyright 2017-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Service-Validator/blob/master/LICENSE.md

import logging
import re
from collections import Counter
from io import StringIO

import redfish_interop_validator.traverseInterop as traverseInterop
import redfish_interop_validator.interop as interop
from redfish_interop_validator.redfish import getType
from redfish_interop_validator.interop import REDFISH_ABSENT

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
                        'rtime': 'n/a',
                        'context': '',
                        'fulltype': '',
                        'rcode': 0,
                        'payload': {}}

    # check for @odata mandatory stuff
    # check for version numbering problems
    # check id if it's the same as URI
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
        resource_obj, return_status = traverseInterop.createResourceObject(
            uriName, URI, expectedJson, expectedType, expectedSchema, parent)

        results[uriName]['rcode'] = return_status

        if not resource_obj:
            counts['inaccessibleResource'] += 1
            my_logger.warning('{}:  This resource is inaccessible and cannot be validated or traversed for links.'.format(URI))
            results[uriName]['warns'] = get_my_capture(my_logger, whandler)
            results[uriName]['payload'] = {}
            return False, counts, results, None, None
        else:
            results[uriName]['payload'] = resource_obj.jsondata

    except traverseInterop.AuthenticationError:
        raise  # re-raise exception
    except Exception as e:
        my_logger.debug('Exception caught while creating ResourceObj', exc_info=1)
        my_logger.error('Unable to gather property info for URI {}: {}'
                        .format(URI, repr(e)))
        counts['exceptionResource'] += 1
        results[uriName]['warns'], results[uriName]['errors'] = get_my_capture(my_logger, whandler), get_my_capture(my_logger, ehandler)
        return False, counts, results, None, None

    counts['passGet'] += 1
    results[uriName]['success'] = True

    # Verify odata type
    profile_resources = profile.get('Resources')

    my_logger.verbose1("*** {}, {}".format(uriName, URI))
    uriName, SchemaFullType, jsondata = uriName, uriName, resource_obj.jsondata
    SchemaType = getType(jsondata.get('@odata.type', 'NoType'))

    oemcheck = traverseInterop.config.get('oemcheck', True)

    collection_limit = traverseInterop.config.get('collectionlimit', {'LogEntry': 20})

    if SchemaType not in profile_resources:
        my_logger.verbose1('Visited {}, type {}'.format(URI, SchemaType))
        # Get all links available
        links, limited_links = getURIsInProperty(jsondata, uriName, oemcheck, collection_limit)
        return True, counts, results, (links, limited_links), resource_obj
    
    if '_count' not in profile_resources[SchemaType]:
        profile_resources[SchemaType]['_count'] = 0
    profile_resources[SchemaType]['_count'] += 1

    # Verify odata_id properly resolves to its parent if holding fragment
    odata_id = resource_obj.jsondata.get('@odata.id', '')
    if '#' in odata_id:
        if parent is not None:
            payload_resolve = traverseInterop.navigateJsonFragment(parent.jsondata, URI)
            if payload_resolve is None:
                my_logger.error('@odata.id of ReferenceableMember does not contain a valid JSON pointer for this payload: {}'.format(odata_id))
                counts['badOdataIdResolution'] += 1
            elif payload_resolve != resource_obj.jsondata:
                my_logger.error('@odata.id of ReferenceableMember does not point to the correct object: {}'.format(odata_id))
                counts['badOdataIdResolution'] += 1
        else:
            my_logger.warning('No parent found with which to test @odata.id of ReferenceableMember')

    # If URI was sampled, get the notation text from traverseInterop.uri_sample_map
    sample_string = traverseInterop.uri_sample_map.get(URI)
    sample_string = sample_string + ', ' if sample_string is not None else ''

    results[uriName]['uri'] = (str(URI))
    results[uriName]['samplemapped'] = (str(sample_string))
    results[uriName]['rtime'] = resource_obj.rtime
    results[uriName]['payload'] = resource_obj.jsondata
    results[uriName]['context'] = resource_obj.context
    results[uriName]['fulltype'] = resource_obj.typename

    my_logger.info('\n')
    my_logger.info("*** %s, %s", URI, SchemaType)
    my_logger.debug("*** %s, %s, %s", expectedType, expectedSchema is not None, expectedJson is not None)
    my_logger.info("\t Type (%s), GET SUCCESS (time: %s)", resource_obj.typename, resource_obj.rtime)

    profile_resources = profile_resources.get(SchemaType)
    try:
        propMessages, propCounts = interop.validateInteropResource(resource_obj, profile_resources, jsondata)
        messages.extend(propMessages)
        counts.update(propCounts)
        my_logger.info('{} of {} tests passed.'.format(counts['pass'] + counts['warn'], counts['totaltests']))
    except Exception:
        my_logger.exception("Something went wrong")
        my_logger.error(
            'Could not finish validation check on this payload')
        counts['exceptionProfilePayload'] += 1
    my_logger.info('%s, %s\n', SchemaFullType, counts)

    # Get all links available
    links, limited_links = getURIsInProperty(resource_obj.jsondata, uriName, oemcheck, collection_limit)

    results[uriName]['warns'], results[uriName]['errors'] = get_my_capture(my_logger, whandler), get_my_capture(my_logger, ehandler)

    pass_val = len(results[uriName]['errors']) == 0
    for key in counts:
        if any(x in key for x in ['problem', 'fail', 'bad', 'exception']):
            pass_val = False
            break
    my_logger.info("\t {}".format('PASS' if pass_val else ' FAIL...'))

    for msg in results[uriName]['messages']:
        msg.parent_results = results
        if msg.success == interop.testResultEnum.NOT_TESTED:
            counts['notTested'] += 1


    return True, counts, results, (links, limited_links), resource_obj


urlCheck = re.compile(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
allowable_annotations = ['@odata.id']

def getURIsInProperty(property, name='Root', oemcheck=True, collection_limit={}):
    my_links, limited_links = {}, {}

    # Return nothing if we are Oem
    if not oemcheck and name == 'Oem':
        return my_links, limited_links
    if isinstance(property, dict):
        for sub_name, value in property.items():
            if '@' in sub_name and sub_name.lower() not in allowable_annotations:
                continue
            if isinstance(value, str) and sub_name.lower() in ['@odata.id']:
                my_link = getURIfromOdata(value)
                if my_link:
                    if '/Oem/' not in my_link:
                        my_links[name] = my_link
                    if '/Oem/' in my_link and oemcheck:
                        my_links[name] = my_link
            else:
                new_links, new_limited_links = getURIsInProperty(value, "{}:{}".format(name, sub_name), oemcheck)
                limited_links.update(new_limited_links)
                parent_type = property.get('@odata.type', '')
                if sub_name == 'Members' and 'Collection' in parent_type:
                    my_type = getType(parent_type).split('Collection')[0]
                    if my_type in collection_limit:
                        new_limited_links = {x: new_links[x] for x in list(new_links.keys())[collection_limit[my_type]:]}
                        new_links = {x: new_links[x] for x in list(new_links.keys())[:collection_limit[my_type]]}
                        limited_links.update(new_limited_links)
                my_links.update(new_links)
    if isinstance(property, list):
        for n, x in enumerate(property):
            new_links, new_limited_links = getURIsInProperty(x, "{}#{}".format(name, n), oemcheck)
            limited_links.update(new_limited_links)
            my_links.update(new_links)
    return my_links, limited_links


def getURIfromOdata(property):
    if '.json' not in property[:-5].lower():
        if '/redfish/v1' in property or urlCheck.match(property):
            return property
    return None

            
def validateURITree(URI, profile, uriName, expectedType=None, expectedSchema=None, expectedJson=None):
    """name
    Validates a Tree of URIs, traversing from the first given
    """
    allLinks = set()
    allLinks.add(URI.rstrip('/'))
    refLinks = list()

    # Resource level validation
    message_counts = Counter()
    error_messages = StringIO()
    message_list = []
    resource_stats = {}

    # Validate top URI
    validateSuccess, counts, results, links, resource_obj = \
        validateSingleURI(URI, profile, uriName, expectedType, expectedSchema, expectedJson)
    
    links, limited_links = links if links else ({}, {})
    for skipped_link in limited_links:
        allLinks.add(limited_links[skipped_link])

    if resource_obj:
        SchemaType = getType(resource_obj.jsondata.get('@odata.type', 'NoType'))
        resource_stats[SchemaType] = {
            "Exists": True,
            "Writeable": False,
            "URIsFound": [URI.rstrip('/')],
            "SubordinateTo": set(),
            "UseCasesFound": set()
        }

    # parent first, then child execution
    # do top level root first, then do each child root, then their children...
    # hold refs for last (less recursion)
    if validateSuccess:
        serviceVersion = profile.get("Protocol")
        if serviceVersion is not None and uriName == 'ServiceRoot':
            serviceVersion = serviceVersion.get('MinVersion', '1.0.0')
            msg, m_success = interop.validateMinVersion(resource_obj.jsondata.get("RedfishVersion", "0"), serviceVersion)
            message_list.append(msg)

        currentLinks = [(link, links[link], resource_obj) for link in links]
        # todo : churning a lot of links, causing possible slowdown even with set checks
        while len(currentLinks) > 0:
            newLinks = list()
            for linkName, link, parent in currentLinks:

                if link is None or link.rstrip('/') in allLinks:
                    continue
            
                if '#' in link:
                    # NOTE: Skips referenced Links (using pound signs), this program currently only works with direct links
                    continue

                if refLinks is not currentLinks and ('Links' in linkName.split('.') or 'RelatedItem' in linkName.split('.') or 'Redundancy' in linkName.split('.')):
                    refLinks.append((linkName, link, parent))
                    continue

                # NOTE: unable to determine autoexpanded resources without Schema
                else:
                    linkSuccess, linkCounts, linkResults, inner_links, linkobj = \
                        validateSingleURI(link, profile, linkName, parent=parent)

                allLinks.add(link.rstrip('/'))

                results.update(linkResults)
            
                if not linkSuccess:
                    continue

                inner_links, inner_limited_links = inner_links

                for skipped_link in inner_limited_links:
                    allLinks.add(inner_limited_links[skipped_link])

                innerLinksTuple = [(link, inner_links[link], linkobj) for link in inner_links]
                newLinks.extend(innerLinksTuple)
                SchemaType = getType(linkobj.jsondata.get('@odata.type', 'NoType'))

                subordinate_tree = []

                current_parent = linkobj.parent
                while current_parent:
                    parentType = getType(current_parent.jsondata.get('@odata.type', 'NoType'))
                    subordinate_tree.append(parentType)
                    current_parent = current_parent.parent

                # Search for UseCase.USECASENAME
                usecases_found = [msg.name.split('.')[-1] for msg in linkResults[linkName]['messages'] if 'UseCase' == msg.name.split('.')[0]]

                if resource_stats.get(SchemaType) is None:
                    resource_stats[SchemaType] = {
                        "Exists": True,
                        "Writeable": False,
                        "URIsFound": [link.rstrip('/')],
                        "SubordinateTo": set([tuple(reversed(subordinate_tree))]),
                        "UseCasesFound": set(usecases_found),
                    }
                else:
                    resource_stats[SchemaType]['Exists'] = True
                    resource_stats[SchemaType]['URIsFound'].append(link.rstrip('/'))
                    resource_stats[SchemaType]['SubordinateTo'].add(tuple(reversed(subordinate_tree)))
                    resource_stats[SchemaType]['UseCasesFound'] = resource_stats[SchemaType]['UseCasesFound'].union(usecases_found)

            if refLinks is not currentLinks and len(newLinks) == 0 and len(refLinks) > 0:
                currentLinks = refLinks
            else:
                currentLinks = newLinks

        my_logger.info('Service Level Checks')
        # NOTE: readrequirements will likely be errors when using --payload outside of root
        
        # For every resource check ReadRequirement
        # TODO: verify if IfImplemented should report a fail if any fails exist.  Also verify the same for Recommended
        resources_in_profile = profile.get('Resources', [])
        for resource_type in resources_in_profile:
            profile_entry = resources_in_profile[resource_type]

            if 'PropertyRequirements' in profile_entry:
                msgs = interop.validateComparisonAnyOfAllOf(profile_entry['PropertyRequirements'], resource_type)
                message_list.extend(msgs)

            does_resource_exist, expected_requirement = False, None

            resource_exists, uris_found, subs_found = False, [], []

            # If exist and for what URIs...
            if resource_type in resource_stats:
                resource_exists = resource_stats[resource_type]['Exists']
                uris_found = resource_stats[resource_type]['URIsFound']
                subs_found = resource_stats[resource_type]['SubordinateTo']
                usecases_found = resource_stats[resource_type]['UseCasesFound']

            # Before all else, UseCases takes priority
            if 'UseCases' in profile_entry:
                # For each use case, apply the Requirement
                for use_case in profile_entry['UseCases']:
                    entry_title = use_case.get("UseCaseTitle", "NoName").replace(' ', '_')
                    expected_requirement = use_case.get("ReadRequirement", "Mandatory")
                    uris_applied = use_case.get("URIs")

                    if uris_applied:
                        does_resource_exist = any([interop.compareRedfishURI(uris_applied, uri) for uri in uris_found])
                    else:
                        does_resource_exist = resource_exists

                    does_resource_exist = does_resource_exist and entry_title in usecases_found

                    my_logger.info('Validating UseCase {} of {} ReadRequirement'.format(entry_title, resource_type))

                    my_msg, _ = interop.validateRequirementResource(expected_requirement, 'Exists' if does_resource_exist else REDFISH_ABSENT)
                    my_msg.name = 'UseCase.{}.{}'.format(entry_title, my_msg.name)
                    if uris_applied:
                        my_msg.expected = "{} at {}".format(my_msg.expected, ", ".join(uris_applied))
                    message_list.append(my_msg)
                continue  

            # Check conditionals, if it applies, get its requirement
            elif "ConditionalRequirements" in profile_entry:
                for condition in profile_entry['ConditionalRequirements']:
                    uris_applied = condition.get("URIs")
                    subordinate_condition = condition.get("SubordinateToResource")
                    # Check if we have valid URIs for this conditional
                    if uris_applied:
                        does_resource_exist = any([interop.compareRedfishURI(uris_applied, uri) for uri in uris_found])
                        my_logger.info('Checking if any {} in {}: {}'.format(uris_found, uris_applied, does_resource_exist))
                    # Or check if we are underneath the correct resource chain
                    elif subordinate_condition:
                        does_resource_exist = any([(tuple((subordinate_condition))) == chain[-len(subordinate_condition):] for chain in subs_found])
                        my_logger.info('Checking if any {} matches {}: {}'.format([x for x in subs_found], subordinate_condition, does_resource_exist))
                    # warn user if Conditional has no appropriate conditions to use
                    else:
                        does_resource_exist = resource_exists
                        my_logger.warn('This resource {} has no valid Conditional in ConditionalRequirements'.format(resource_type))

                    # if we have a ReadRequirement...
                    expected_requirement = condition.get("ReadRequirement")
                    if expected_requirement:
                        my_logger.info('Validating {} Conditional ReadRequirement'.format(resource_type))
                        my_msg, _ = interop.validateRequirementResource(expected_requirement, 'Exists' if does_resource_exist else REDFISH_ABSENT)
                        my_msg.name = '{}.Conditional.{}'.format(resource_type, my_msg.name)
                        if uris_applied:
                            my_msg.expected = "{} at {}".format(my_msg.expected, ", ".join(uris_applied))
                        if subordinate_condition:
                            my_msg.expected = "{} under {}".format(my_msg.expected, ", ".join(subordinate_condition))
                        message_list.append(my_msg)

            # Outside of ConditionalRequirements, check just for URIs
            # TODO: Verify if this should run if ConditionalRequirements exists
            expected_requirement = profile_entry.get("ReadRequirement", "Mandatory")
            uris_applied = profile_entry.get("URIs")

            if uris_applied:
                does_resource_exist = any([interop.compareRedfishURI(uris_applied, uri) for uri in uris_found])
            else:
                does_resource_exist = resource_exists

            my_logger.info('Validating {} ReadRequirement'.format(resource_type))
            my_msg, _ = interop.validateRequirementResource(expected_requirement, 'Exists' if does_resource_exist else REDFISH_ABSENT)
            my_msg.name = '{}.{}'.format(resource_type, my_msg.name)
            if uris_applied:
                my_msg.expected = "{} at {}".format(my_msg.expected, ", ".join(uris_applied))
            message_list.append(my_msg)
            
    # interop service level checks
    finalResults = {}

    for item in message_list:
        if item.success == interop.testResultEnum.WARN:
            message_counts['warn'] += 1
        elif item.success == interop.testResultEnum.PASS:
            message_counts['pass'] += 1
        elif item.success == interop.testResultEnum.FAIL:
            message_counts['fail.{}'.format(item.name)] += 1

    finalResults['n/a'] = {'uri': "Service Level Requirements", 'success': message_counts.get('fail', 0) == 0,
                           'counts': message_counts,
                           'messages': message_list, 'errors': error_messages.getvalue(), 'warns': '',
                           'rtime': None, 'context': '', 'fulltype': ''}
    finalResults.update(results)
    error_messages.close()

    return validateSuccess, counts, finalResults, refLinks, resource_obj
