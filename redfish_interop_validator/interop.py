
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

import re
from enum import Enum
from collections import Counter

import logging
from redfish_interop_validator.redfish import getNamespaceUnversioned, getType, getNamespace
from redfish_interop_validator.traverseInterop import callResourceURI
my_logger = logging.getLogger()
my_logger.setLevel(logging.DEBUG)

config = {'WarnRecommended': False, 'WriteCheck': False}


class testResultEnum(Enum):
    FAIL = 'FAIL'
    NOPASS = 'NO PASS'
    PASS = 'PASS'
    WARN = 'WARN'
    OK = 'OK'
    NA = 'N/A'
    NOT_TESTED = 'NOT TESTED'


REDFISH_ABSENT = 'n/a'


class msgInterop:
    def __init__(self, name, profile_entry, expected, actual, success):
        self.name = name
        self.entry = profile_entry
        self.expected = expected
        self.actual = actual
        self.ignore = False
        if isinstance(success, bool):
            self.success = testResultEnum.PASS if success else testResultEnum.FAIL
        else:
            self.success = success
        self.parent_results = None


def validateComparisonAnyOfAllOf(profile_entry, property_path="Unspecified"):
    """
    Gather comparison information after processing all Resources on system
    """
    all_msgs = []
    for key in profile_entry:
        property_profile = profile_entry[key]
        my_compare = property_profile.get('Comparison', 'AnyOf')

        if property_profile.get('Values') and my_compare in ['AnyOf', 'AllOf']:
            my_msgs = property_profile.get('_msgs', [])
            my_values, expected_values = [m.actual for m in my_msgs], property_profile['Values']

            my_logger.info('Validating {} Comparison for {} : {}'.format(my_compare, property_path, key))
            my_logger.info("  {},  Expecting {}".format(my_values, expected_values))

            if not len(my_msgs) and property_profile.get('ReadRequirement', 'Mandatory') != 'Mandatory':
                continue

            msg_name = 'Comparison.{}.{}'.format(property_path, key)

            top_msg = msgInterop(msg_name, my_compare, expected_values, my_values, False)
            all_msgs.append(top_msg)

            # NOPASS by default, if the check fails but the value is still in the array
            # OK if passing, FAIL if check fails and value is not in array
            for msg in my_msgs:
                msg.ignore = False
                msg.success = testResultEnum.NOPASS
                msg.expected = '{} {} ({})'.format(msg.expected, expected_values, "Across All Resources")

            if my_compare == 'AnyOf':
                if any([x in my_values for x in expected_values]):
                    my_logger.info('  PASS')
                    top_msg.success = testResultEnum.PASS
                    for msg in my_msgs:
                        msg.success = testResultEnum.OK
                        if msg.actual in expected_values:
                            msg.success = testResultEnum.PASS
                else:
                    my_logger.info('  FAIL')
                    for msg in my_msgs:
                        msg.success = testResultEnum.FAIL

            if my_compare == 'AllOf':
                if all([x in my_values for x in expected_values]):
                    my_logger.info('  PASS')
                    top_msg.success = testResultEnum.PASS
                    for msg in my_msgs:
                        msg.success = testResultEnum.OK
                else:
                    my_logger.info('  FAIL')
                    for msg in my_msgs:
                        if msg.actual not in expected_values:
                            msg.success = testResultEnum.FAIL

        if property_profile.get('PropertyRequirements'):
            new_msgs = validateComparisonAnyOfAllOf(property_profile.get('PropertyRequirements'), '.'.join([property_path, key]))
            all_msgs.extend(new_msgs)
        
    return all_msgs


def validateRequirement(profile_entry, rf_payload_item=None, conditional=False, parent_object_tuple=None):
    """
    Validates Requirement profile_entry

    By default, only the first parameter is necessary and will always Pass if none given
    """
    propDoesNotExist = (rf_payload_item == REDFISH_ABSENT)
    my_logger.debug('Testing ReadRequirement \n\texpected:' + str(profile_entry) + ', exists: ' + str(not propDoesNotExist))
    # If we're not mandatory, pass automatically, else fail
    # However, we have other entries "IfImplemented" and "Conditional"
    # note: Mandatory is default!! if present in the profile.  Make sure this is made sure.
    # For DNE entries "IfImplemented" and "Recommended" result with not applicable
    original_profile_entry = profile_entry

    if profile_entry == "IfPopulated":
        my_status = 'Enabled'
        if parent_object_tuple:
            my_state = parent_object_tuple[0].get('Status')
            my_status = my_state.get('State') if my_state else my_status
        if my_status != 'Absent':
            profile_entry = 'Mandatory'
        else:
            profile_entry = 'Recommended'

    if profile_entry == "Conditional" and conditional:
        profile_entry = "Mandatory"

    paramPass = not profile_entry == "Mandatory" or \
        profile_entry == "Mandatory" and not propDoesNotExist

    if profile_entry == "IfImplemented":
        if propDoesNotExist:
            paramPass = testResultEnum.NA
        else:
            my_logger.debug('\tItem cannot be tested for Implementation')

    if profile_entry == "Recommended" and propDoesNotExist:
        my_logger.info('\tItem is recommended but does not exist')
        if config['WarnRecommended']:
            my_logger.warning('\tItem is recommended but does not exist, escalating to WARN')
            paramPass = testResultEnum.WARN
        else:
            paramPass = testResultEnum.NA

    my_logger.debug('\tpass ' + str(paramPass))
    return msgInterop('ReadRequirement', original_profile_entry, 'Must Exist' if profile_entry == "Mandatory" else 'Any', 'Exists' if not propDoesNotExist else 'DNE', paramPass),\
        paramPass


def isPropertyValid(profilePropName, rObj):
    for prop in rObj.getResourceProperties():
        if profilePropName == prop.propChild:
            return None, True
    my_logger.error('{} - Does not exist in ResourceType Schema, please consult profile provided'.format(profilePropName))
    return msgInterop('PropertyValidity', profilePropName, 'Should Exist', 'in ResourceType Schema', False), False


def validateMinCount(alist, length, annotation=0):
    """
    Validates Mincount annotation
    """
    my_logger.debug('Testing minCount \n\texpected:' + str(length) + ', val:' + str(annotation))
    paramPass = len(alist) >= length or annotation >= length
    my_logger.debug('\tpass ' + str(paramPass))
    return msgInterop('MinCount', length, '<=', annotation if annotation > len(alist) else len(alist), paramPass),\
        paramPass


def validateSupportedValues(enumlist, annotation):
    """
    Validates SupportedVals annotation
    """
    my_logger.debug('Testing supportedValues \n\t:' + str(enumlist) + ', exists:' + str(annotation))
    paramPass = True
    for item in enumlist:
        paramPass = item in annotation
        if not paramPass:
            break
    my_logger.debug('\tpass ' + str(paramPass))
    return msgInterop('SupportedValues', enumlist, 'included in...', annotation, paramPass),\
        paramPass


def findPropItemforString(propObj, itemname):
    """
    Finds an appropriate object for an item
    """
    for prop in propObj.getResourceProperties():
        rf_payloadName = prop.name.split(':')[-1]
        if itemname == rf_payloadName:
            return prop
    return None


def validateWriteRequirement(profile_entry, parent_object_payload, resource_headers, item_name):
    """
    Validates if a property is WriteRequirement or not
    """
    my_logger.verbose1('Is property writeable \n\t' + str(profile_entry))

    if profile_entry == "Mandatory" or profile_entry == "Supported":
        result_not_supported = testResultEnum.FAIL
        expected_str = "Must Be Writable"
    elif profile_entry == "Recommended":
        if config['WarnRecommended']:
            result_not_supported = testResultEnum.WARN
        else:
            result_not_supported = testResultEnum.NA
        expected_str = "Recommended"
    else:
        result_not_supported = testResultEnum.NA
        expected_str = "Any"

    # Check for Allow header, warn if missing
    if resource_headers and 'Allow' in resource_headers:
        writeable = 'PATCH' in resource_headers['Allow']
        if not writeable:
            if profile_entry == "Mandatory":
                my_logger.error('PATCH in Allow header not available, property is not writeable ' + str(profile_entry))
            return msgInterop('WriteRequirement', profile_entry, expected_str, 'PATCH not supported', result_not_supported), True
    else:
        my_logger.warning('Unable to test writeable property, no Allow header available ' + str(profile_entry))
        return msgInterop('WriteRequirement', profile_entry, expected_str, 'No Allow response header', testResultEnum.NOT_TESTED), True
    
    redfish_payload, _ = parent_object_payload

    # Get Writeable Properties
    if '@Redfish.WriteableProperties' not in redfish_payload:
        my_logger.warning('Unable to test writeable property, no @Redfish.WriteableProperties available at the property level ' + str(profile_entry))
        return msgInterop('WriteRequirement', profile_entry, expected_str, '@Redfish.WriteableProperties not in response', testResultEnum.NOT_TESTED), True

    writeable_properties = redfish_payload['@Redfish.WriteableProperties']
    if not isinstance(writeable_properties, list):
        my_logger.warning('Unable to test writeable property, @Redfish.WriteableProperties is not an array ' + str(profile_entry))
        return msgInterop('WriteRequirement', profile_entry, expected_str, '@Redfish.WriteableProperties not an array', testResultEnum.WARN), True

    is_writeable = item_name in writeable_properties

    return msgInterop('WriteRequirement', profile_entry, expected_str, 'Writable' if is_writeable else 'Not Writable',
                      testResultEnum.PASS if is_writeable else result_not_supported), True

def checkComparison(val, compareType, target):
    """
    Validate a given comparison option, given a value and a target set
    """
    my_logger.verbose1('Testing a comparison \n\t' + str((val, compareType, target)))
    vallist = val if isinstance(val, list) else [val]
    paramPass = False
    if compareType is None:
        my_logger.error('CompareType not available in payload')

    # NOTE: In our current usage, AnyOf and AllOf in this context is only for ConditionalRequirements -> CompareProperty
    # Which checks if a particular property inside of this instance applies
    if compareType == "AnyOf":
        for item in vallist:
            paramPass = item in target
            if paramPass:
                break
            else:
                continue

    if compareType == "AllOf":
        alltarget = set()
        for item in vallist:
            paramPass = item in target and item not in alltarget
            if paramPass:
                alltarget.add(item)
                if len(alltarget) == len(target):
                    break
            else:
                continue
        paramPass = len(alltarget) == len(target)
    if compareType == "LinkToResource":
        if val == REDFISH_ABSENT:
            paramPass = False
        else:
            vallink = val.get('@odata.id')
            success, rf_payload, code, elapsed, _ = callResourceURI(vallink)
            if success:
                ourType = rf_payload.get('@odata.type')
                if ourType is not None:
                    SchemaType = getType(ourType)
                    paramPass = SchemaType in target
                else:
                    paramPass = False
            else:
                paramPass = False

    if compareType == "Absent":
        paramPass = val == REDFISH_ABSENT
    if compareType == "Present":
        paramPass = val != REDFISH_ABSENT

    if isinstance(target, list):
        if compareType == "Equal":
            paramPass = val in target
        elif compareType == "NotEqual":
            paramPass = val not in target
        else:
            for value in target:
                if compareType == "GreaterThan":
                    paramPass = val > value
                if compareType == "GreaterThanOrEqual":
                    paramPass = val >= value
                if compareType == "LessThan":
                    paramPass = val < value
                if compareType == "LessThanOrEqual":
                    paramPass = val <= value
                if paramPass is False:
                    break
    my_logger.debug('\tpass ' + str(paramPass))
    return msgInterop('Comparison', target, compareType, val, paramPass),\
        paramPass


def validateMembers(members, profile_entry, annotation):
    """
    Validate an profile_entry of Members and its count annotation
    """
    my_logger.debug('Testing members \n\t' + str((members, profile_entry, annotation)))
    if not validateRequirement('Mandatory', members):
        return False
    if "MinCount" in profile_entry:
        mincount, mincountpass = validateMinCount(members, profile_entry["MinCount"], annotation)
        mincount.name = 'MembersMinCount'
    return mincount, mincountpass


def validateMinVersion(version, profile_entry):
    """
    Checks for the minimum version of a resource's type
    """
    my_logger.debug('Testing minVersion \n\t' + str((version, profile_entry)))
    # If version doesn't contain version as is, try it as v#_#_#
    profile_entry_split = profile_entry.split('.')
    # get version from payload
    if(re.match('#([a-zA-Z0-9_.-]*\.)+[a-zA-Z0-9_.-]*', version) is not None):
        v_payload = getNamespace(version).split('.', 1)[-1]
        v_payload = v_payload.replace('v', '')
        if ('_' in v_payload):
            payload_split = v_payload.split('_')
        else:
            payload_split = v_payload.split('.')
    else:
        payload_split = version.split('.')

    paramPass = True
    for a, b in zip(profile_entry_split, payload_split):
        if b.isnumeric() and a.isnumeric() and b is not None and a is not None:
            b = int(b)
            a = int(a)
        else:
            b = 0 if b is None else b
            a = 0 if a is None else b
        if type(b) is not type(a):
            break
        if (b > a):
            break
        if (b < a):
            paramPass = False
            break

    # use string comparison, given version numbering is accurate to regex
    my_logger.debug('\tpass ' + str(paramPass))
    return msgInterop('MinVersion', profile_entry, '<=', version, paramPass),\
        paramPass


def checkConditionalRequirement(propResourceObj, profile_entry, rf_payload_tuple):
    """
    Returns boolean if profile_entry's conditional is true or false
    """
    my_logger.debug('Evaluating conditionalRequirements')
    if "SubordinateToResource" in profile_entry:
        isSubordinate = False
        # iterate through parents via resourceObj
        # list must be reversed to work backwards
        resourceParent = propResourceObj.parent
        for expectedParent in reversed(profile_entry["SubordinateToResource"]):
            if resourceParent is not None:
                parentType = getType(resourceParent.jsondata.get('@odata.type', 'NoType'))
                isSubordinate = parentType == expectedParent
                my_logger.debug('\tsubordinance ' +
                               str(parentType) + ' ' + str(isSubordinate))
                resourceParent = resourceParent.parent
            else:
                my_logger.debug('no parent')
                isSubordinate = False
        return isSubordinate
    elif "CompareProperty" in profile_entry:
        # find property in json payload by working backwards thru objects
        # rf_payload tuple is designed just for this piece, since there is
        # no parent in dictionaries
        if profile_entry["CompareProperty"][0] == '/':
            comparePropNames = profile_entry["CompareProperty"].split('/')[1:]
        else:
            comparePropNames = [profile_entry["CompareProperty"]]
        if "CompareType" not in profile_entry:
            my_logger.error("Invalid Profile - CompareType is required for CompareProperty but not found")
            raise ValueError('CompareType missing with CompareProperty')
        if "CompareValues" not in profile_entry and profile_entry['CompareType'] not in ['Absent', 'Present']:
            my_logger.error("Invalid Profile - CompareValues is required for CompareProperty but not found")
            raise ValueError('CompareValues missing with CompareProperty')
        if "CompareValues" in profile_entry and profile_entry['CompareType'] in ['Absent', 'Present']:
            my_logger.warning("Invalid Profile - CompareValues is not required for CompareProperty Absent or Present ")

        rf_payload_item, rf_payload = rf_payload_tuple
        while rf_payload is not None and (not isinstance(rf_payload_item, dict) or comparePropNames[0] not in rf_payload_item):
            rf_payload_item, rf_payload = rf_payload

        if rf_payload_item is None:
            my_logger.error('Could not acquire expected CompareProperty {}'.format(comparePropNames[0]))
            return False

        compareProp = rf_payload_item.get(comparePropNames[0], REDFISH_ABSENT)
        if (compareProp != REDFISH_ABSENT) and len(comparePropNames) > 1:
            for comparePropName in comparePropNames[1:]:
                compareProp = compareProp.get(comparePropName, REDFISH_ABSENT)
                if compareProp == REDFISH_ABSENT:
                    break
        # compatability with old version, deprecate with versioning
        compareType = profile_entry.get("CompareType", profile_entry.get("Comparison"))
        return checkComparison(compareProp, compareType, profile_entry.get("CompareValues", []))[1]
    else:
        my_logger.error("Invalid Profile - No conditional given")
        raise ValueError('No conditional given for Comparison')


def find_key_in_payload(path_to_key, redfish_parent_payload):
    """
    Finds a key in the payload tuple provided

    :param path_to_key: Single key name or RFC6901 JSON Pointer
    :param redfish_parent_payload: Payload Tuple (payload, parent_payload)
    :return: True if exist, False otherwise
    :rtype: boolean
    """    
    # Profile entry is a path
    key_exists = False
    if path_to_key[0] == '/':
        # Generate RFC6901 Json Pointer
        replaced_by_property_path = path_to_key.split('/')[1:]
        # Get our complete payload
        my_parent_payload = redfish_parent_payload
        while my_parent_payload is not None:
            current_target, my_parent_payload = my_parent_payload

        key_exists = True
        for key in replaced_by_property_path:
            if isinstance(current_target, dict) and current_target.get(key) is not None:
                current_target = current_target[key]
                continue
            else:
                key_exists = False
    # Profile entry is a single variable
    else:
        replaced_by_property_name = path_to_key
        current_target, my_parent_payload = redfish_parent_payload
        if current_target.get(replaced_by_property_name) is not None:
            key_exists = True
        else:
            key_exists = False
    return key_exists


def validatePropertyRequirement(propResourceObj, profile_entry, rf_payload_tuple, item_name):
    """
    Validate PropertyRequirements
    """
    msgs = []
    counts = Counter()

    # TODO: Change rf_payload_tuple to a more natural implementation (like an object)
    redfish_value, redfish_parent_payload = rf_payload_tuple

    if profile_entry is None or len(profile_entry) == 0:
        my_logger.debug('there are no requirements for this prop')
    else:
        my_logger.debug('propRequirement with value: ' + str(redfish_value if not isinstance(redfish_value, dict) else 'dict'))

    if "ReplacesProperty" in profile_entry and redfish_value == REDFISH_ABSENT:
        my_path_entry = profile_entry.get("ReplacesProperty")
        replacement_property_exists = find_key_in_payload(my_path_entry, redfish_parent_payload)

        new_msg = msgInterop("{}.{}".format(item_name, "ReplacesProperty"), profile_entry["ReplacesProperty"], "-",
                            "Exists" if replacement_property_exists else "DNE", testResultEnum.WARN if replacement_property_exists else testResultEnum.OK)
        msgs.append(new_msg)
        if replacement_property_exists:
            my_logger.warn('{}: This property replaces deprecated property {}, but does not exist, service should implement {}'.format(item_name, my_path_entry, item_name))
            return msgs, counts
        else:
            if profile_entry.get('ReadRequirement', 'Mandatory'):
                my_logger.error('{}: Replaced property {} does not exist, {} should be implemented'.format(item_name, my_path_entry, item_name))

    if "ReplacedByProperty" in profile_entry:
        my_path_entry = profile_entry.get("ReplacedByProperty")
        replacement_property_exists = find_key_in_payload(my_path_entry, redfish_parent_payload)
        
        new_msg = msgInterop("{}.{}".format(item_name, "ReplacedByProperty"), profile_entry["ReplacedByProperty"], "-",
                            "Exists" if replacement_property_exists else "DNE", testResultEnum.PASS if replacement_property_exists else testResultEnum.OK)
        msgs.append(new_msg)
        if replacement_property_exists:
            my_logger.info('{}: Replacement property exists, step out of validating'.format(item_name))
            return msgs, counts
        else:
            my_logger.info('{}: Replacement property does not exist, continue validating'.format(item_name))

    # Check the conditional requirements first or the requirements won't apply correctly against
    # a list.
    if "ConditionalRequirements" in profile_entry:
        innerList = profile_entry["ConditionalRequirements"]
        for item in innerList:
            try:
                if checkConditionalRequirement(propResourceObj, item, rf_payload_tuple):
                    my_logger.info("\tCondition DOES apply")
                    conditionalMsgs, conditionalCounts = validatePropertyRequirement(
                        propResourceObj, item, rf_payload_tuple, item_name)
                    counts.update(conditionalCounts)
                    for item in conditionalMsgs:
                        item.name = item.name.replace('.', '.Conditional.', 1)
                    msgs.extend(conditionalMsgs)
                else:
                    my_logger.info("\tCondition does not apply")
            except ValueError as e:
                my_logger.info("\tCondition was skipped due to payload error")
                counts['errorProfileComparisonError'] += 1

    # If we're working with a list, then consider MinCount, Comparisons, then execute on each item
    # list based comparisons include AnyOf and AllOf
    if isinstance(redfish_value, list):
        my_logger.debug("inside of a list: " + item_name)
        if "MinCount" in profile_entry:
            msg, success = validateMinCount(redfish_value, profile_entry["MinCount"],
                                redfish_parent_payload[0].get(item_name.split('.')[-1] + '@odata.count', 0))
            if not success:
                my_logger.error("MinCount failed")
            msgs.append(msg)
            msg.name = item_name + '.' + msg.name
        cnt = 0
        for item in redfish_value:
            listmsgs, listcounts = validatePropertyRequirement(
                propResourceObj, profile_entry, (item, redfish_parent_payload), item_name + '#' + str(cnt))
            counts.update(listcounts)
            msgs.extend(listmsgs)
            cnt += 1

    else:
        # consider requirement before anything else
        # problem: if dne, skip?

        # Read Requirement is default mandatory if not present
        msg, success = validateRequirement(profile_entry.get('ReadRequirement', 'Mandatory'), redfish_value, parent_object_tuple=redfish_parent_payload)
        msgs.append(msg)
        msg.name = item_name + '.' + msg.name

        if "WriteRequirement" in profile_entry:
            headers = propResourceObj.headers
            msg, success = validateWriteRequirement(profile_entry.get('WriteRequirement', 'Mandatory'), redfish_parent_payload, headers, item_name)
            msgs.append(msg)
            msg.name = item_name + '.' + msg.name
            if not success:
                my_logger.error("WriteRequirement failed")

        if "MinSupportValues" in profile_entry:
            msg, success = validateSupportedValues(
                    profile_entry["MinSupportValues"],
                    redfish_parent_payload[0].get(item_name.split('.')[-1] + '@Redfish.AllowableValues', []))
            msgs.append(msg)
            msg.name = item_name + '.' + msg.name
            if not success:
                my_logger.error("MinSupportValues failed")

        if "Values" in profile_entry:
            # Default to AnyOf

            my_compare = profile_entry.get("Comparison", "AnyOf")
            msg, success = checkComparison(redfish_value, my_compare, profile_entry.get("Values", []))
            msgs.append(msg)
            msg.name = item_name + '.' + msg.name

            # Embed test results into profile, going forward seems to be the quick option outside of making a proper test object
            if my_compare in ['AnyOf', 'AllOf']:
                msg.ignore = True
                if not profile_entry.get('_msgs'):
                    profile_entry['_msgs'] = []
                profile_entry['_msgs'].append(msg)
            elif not success:
                my_logger.error("Comparison failed")

        if "PropertyRequirements" in profile_entry:
            innerDict = profile_entry["PropertyRequirements"]
            if isinstance(redfish_value, dict):
                for item in innerDict:
                    my_logger.debug('inside complex ' + item_name + '.' + item)
                    complexMsgs, complexCounts = validatePropertyRequirement(
                        propResourceObj, innerDict[item], (redfish_value.get(item, REDFISH_ABSENT), rf_payload_tuple), item)
                    msgs.extend(complexMsgs)
                    counts.update(complexCounts)
            else:
                my_logger.info('complex {} is missing or not a dictionary'.format(item_name))
    return msgs, counts


def validateActionRequirement(profile_entry, rf_payload_tuple, actionname):
    """
    Validate Requirements for one action
    """
    rf_payload_item, rf_payload = rf_payload_tuple
    rf_payload_action = None
    counts = Counter()
    msgs = []
    my_logger.verbose1('actionRequirement \n\tval: ' + str(rf_payload_item if not isinstance(
        rf_payload_item, dict) else 'dict') + ' ' + str(profile_entry))

    if "ReadRequirement" in profile_entry:
        # problem: if dne, skip
        msg, success = validateRequirement(profile_entry.get('ReadRequirement', "Mandatory"), rf_payload_item)
        msgs.append(msg)
        msg.name = actionname + '.' + msg.name
        msg.success = testResultEnum.PASS if success else testResultEnum.FAIL

    propDoesNotExist = (rf_payload_item == REDFISH_ABSENT)
    if propDoesNotExist:
        return msgs, counts
    if "@Redfish.ActionInfo" in rf_payload_item:
        vallink = rf_payload_item['@Redfish.ActionInfo']
        success, rf_payload_action, code, elapsed, _ = callResourceURI(vallink)
        if not success:
            rf_payload_action = None

    # problem: if dne, skip
    if "Parameters" in profile_entry:
        innerDict = profile_entry["Parameters"]
        # problem: if dne, skip
        # assume mandatory
        for k in innerDict:
            item = innerDict[k]
            values_array = None
            if rf_payload_action is not None:
                action_by_name = rf_payload_action['Parameters']
                my_action = [x for x in action_by_name if x['Name'] == k]
                if my_action:
                    values_array = my_action[0].get('AllowableValues')
            if values_array is None:
                values_array = rf_payload_item.get(str(k) + '@Redfish.AllowableValues', REDFISH_ABSENT)
            if values_array == REDFISH_ABSENT:
                my_logger.warning('\tNo such ActionInfo exists for this Action, and no AllowableValues exists.  Cannot validate the following parameters: {}'.format(k))
                msg = msgInterop('', item, '-', '-', testResultEnum.WARN)
                msg.name = "{}.{}.{}".format(actionname, k, msg.name)
                msgs.append(msg)
            else:
                msg, success = validateRequirement(item.get('ReadRequirement', "Mandatory"), values_array)
                msgs.append(msg)
                msg.name = "{}.{}.{}".format(actionname, k, msg.name)
                if "ParameterValues" in item:
                    msg, success = validateSupportedValues(
                            item["ParameterValues"], values_array)
                    msgs.append(msg)
                    msg.name = "{}.{}.{}".format(actionname, k, msg.name)
                if "RecommendedValues" in item:
                    msg, success = validateSupportedValues(
                            item["RecommendedValues"], values_array)
                    msg.name = msg.name.replace('Supported', 'Recommended')
                    if config['WarnRecommended'] and not success:
                        my_logger.warning('\tRecommended parameters do not all exist, escalating to WARN')
                        msg.success = testResultEnum.WARN
                    elif not success:
                        my_logger.warning('\tRecommended parameters do not all exist, but are not Mandatory')
                        msg.success = testResultEnum.PASS

                    msgs.append(msg)
                    msg.name = "{}.{}.{}".format(actionname, k, msg.name)
    # consider requirement before anything else, what if action
    # if the action doesn't exist, you can't check parameters
    # if it doesn't exist, what should not be checked for action
    return msgs, counts


URI_ID_REGEX = '\{[A-Za-z0-9]*Id\}'

VALID_ID_REGEX = '([A-Za-z0-9.!#$&-;=?\[\]_~])+'


def compareRedfishURI(expected_uris, uri):
    success = False
    # If we have our URIs
    if expected_uris is not None:
        my_uri_regex = "^{}$".format("|".join(expected_uris))
        my_uri_regex = re.sub(URI_ID_REGEX, VALID_ID_REGEX, my_uri_regex)
        success = re.fullmatch(my_uri_regex, uri) is not None
    else:
        success = True
    return success


def checkInteropURI(r_obj, profile_entry):
    """
    Checks if the profile's URI applies to the particular resource
    """
    my_logger.debug('Testing URI \n\t' + str((r_obj.uri, profile_entry)))

    my_id, my_uri = r_obj.jsondata.get('Id'), r_obj.uri
    return compareRedfishURI(profile_entry, my_uri)


def validateInteropResource(propResourceObj, interop_profile, rf_payload):
    """
    Base function that validates a single Interop Resource by its profile_entry
    """
    msgs = []
    my_logger.info('### Validating an InteropResource')
    my_logger.debug(str(interop_profile))
    counts = Counter()
    # rf_payload_tuple provides the chain of dicts containing dicts, needed for CompareProperty
    rf_payload_tuple = (rf_payload, None)

    if "UseCases" in interop_profile:
        for use_case in interop_profile['UseCases']:
            entry_title = use_case.get("UseCaseTitle", "NoName").replace(' ','_')
            my_logger.debug('UseCase {}'.format(entry_title))

            # Check if we have a valid UseCase
            if 'URIs' not in use_case and 'UseCaseKeyProperty' not in use_case:
                my_logger.error('UseCase does not have URIs or UseCaseKeyProperty...')

            if 'UseCaseKeyProperty' in use_case:
                entry_key, entry_comparison, entry_values = use_case['UseCaseKeyProperty'], use_case['UseCaseComparison'], use_case['UseCaseKeyValues']

                _, use_case_applies = checkComparison(rf_payload.get(entry_key), entry_comparison, entry_values)

                # Check if URI applies to this usecase as well
                if 'URIs' in use_case:
                    use_case_applies = checkInteropURI(propResourceObj, use_case['URIs']) and use_case_applies

            elif 'URIs' in use_case:
                use_case_applies = checkInteropURI(propResourceObj, use_case['URIs'])
            
            else:
                use_case_applies = False

            if use_case_applies:
                my_msg = msgInterop("UseCase.{}".format(entry_title), '-', '-', '-', testResultEnum.OK)

                msgs.append(my_msg)

                my_logger.info('Validating using UseCase {}'.format(entry_title))

                # Remove URIs
                new_case = {key: val for key, val in use_case.items() if key not in ['URIs']}

                new_msgs, new_counts = validateInteropResource(propResourceObj, new_case, rf_payload)

                if any([msg.success == testResultEnum.FAIL for msg in new_msgs]):
                    my_msg.success = testResultEnum.FAIL

                msgs.extend(new_msgs)
                counts.update(new_counts)

            else:
                my_logger.info('UseCase {} does not apply'.format(entry_title))

        return msgs, counts
    if "URIs" in interop_profile:
        # Check if the profile requirements apply to this particular instance
        if not checkInteropURI(propResourceObj, interop_profile['URIs']):
            my_logger.info('Skipping resource; URI is not listed')
            return msgs, counts
    if "MinVersion" in interop_profile:
        my_type = propResourceObj.jsondata.get('@odata.type', 'NoType')
        msg, success = validateMinVersion(my_type, interop_profile['MinVersion'])
        msgs.append(msg)
    if "PropertyRequirements" in interop_profile:
        innerDict = interop_profile["PropertyRequirements"]
        for item in innerDict:
            # NOTE: Program no longer performs fuzzy checks for misnamed properties, since there is no schema
            my_logger.info('### Validating PropertyRequirements for {}'.format(item))
            pmsgs, pcounts = validatePropertyRequirement(propResourceObj, innerDict[item], (rf_payload.get(item, REDFISH_ABSENT), rf_payload_tuple), item)
            counts.update(pcounts)
            msgs.extend(pmsgs)
    if "ActionRequirements" in interop_profile:
        innerDict = interop_profile["ActionRequirements"]
        actionsJson = rf_payload.get('Actions', {})
        rf_payloadInnerTuple = (actionsJson, rf_payload_tuple)
        for item in innerDict:
            my_type = getNamespaceUnversioned(propResourceObj.jsondata.get('@odata.type', 'NoType'))
            actionName = my_type + '.' + item
            if actionName in actionsJson:
                my_logger.warning('{} should be #{}'.format(actionName, actionName))
            else:
                actionName = '#' + my_type + '.' + item
            
            amsgs, acounts = validateActionRequirement(innerDict[item], (actionsJson.get(
                actionName, REDFISH_ABSENT), rf_payloadInnerTuple), actionName)
            counts.update(acounts)
            msgs.extend(amsgs)
    if "CreateResource" in interop_profile:
        my_logger.info('Skipping CreateResource')
        pass
    if "DeleteResource" in interop_profile:
        my_logger.info('Skipping DeleteResource')
        pass
    if "UpdateResource" in interop_profile:
        my_logger.info('Skipping UpdateResource')
        pass

    for item in [item for item in msgs if not item.ignore]:
        if item.success == testResultEnum.WARN:
            counts['warn'] += 1
        elif item.success == testResultEnum.PASS:
            counts['pass'] += 1
        elif item.success == testResultEnum.FAIL:
            counts['fail.{}'.format(item.name)] += 1
        counts['totaltests'] += 1
    return msgs, counts
