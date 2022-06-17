
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

import re
from enum import Enum
from collections import Counter

import logging
from common.redfish import getNamespaceUnversioned, getType, getNamespace
from traverseInterop import callResourceURI
my_logger = logging.getLogger()
my_logger.setLevel(logging.DEBUG)

config = {'WarnRecommended': False, 'WriteCheck': False}

class sEnum(Enum):
    FAIL = 'FAIL'
    PASS = 'PASS'
    WARN = 'WARN'


class msgInterop:
    def __init__(self, name, profile_entry, expected, actual, success):
        self.name = name
        self.entry = profile_entry
        self.expected = expected
        self.actual = actual
        if isinstance(success, bool):
            self.success = sEnum.PASS if success else sEnum.FAIL
        else:
            self.success = success
        self.parent = None


def validateRequirement(profile_entry, rf_payload_item=None, conditional=False, parent_object_tuple=None):
    """
    Validates Requirement profile_entry

    By default, only the first parameter is necessary and will always Pass if none given
    """
    propDoesNotExist = (rf_payload_item == 'DNE')
    my_logger.debug('Testing ReadRequirement \n\texpected:' + str(profile_entry) + ', exists: ' + str(not propDoesNotExist))
    # If we're not mandatory, pass automatically, else fail
    # However, we have other entries "IfImplemented" and "Conditional"
    # note: Mandatory is default!! if present in the profile.  Make sure this is made sure.
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
    if profile_entry == "IfImplemented":
        my_logger.debug('\tItem cannot be tested for Implementation')
    paramPass = not profile_entry == "Mandatory" or \
        profile_entry == "Mandatory" and not propDoesNotExist
    if profile_entry == "Recommended" and propDoesNotExist:
        my_logger.info('\tItem is recommended but does not exist')
        if config['WarnRecommended']:
            my_logger.warning('\tItem is recommended but does not exist, escalating to WARN')
            paramPass = sEnum.WARN

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


def validateWriteRequirement(propObj, profile_entry, itemname):
    """
    Validates if a property is WriteRequirement or not
    """
    my_logger.debug('writeable \n\t' + str(profile_entry))
    permission = 'Read'
    expected = "OData.Permission/ReadWrite" if profile_entry else "Any"
    if not config['WriteCheck']:
        paramPass = True
        return msgInterop('WriteRequirement', profile_entry, expected, permission, paramPass),\
            paramPass
    if profile_entry:
        targetProp = findPropItemforString(propObj, itemname.replace('#', ''))
        propAttr = None
        if targetProp is not None:
            propAttr = targetProp.propDict.get('OData.Permissions')
        if propAttr is not None:
            permission = propAttr.get('EnumMember', 'Read')
            paramPass = permission \
                == "OData.Permission/ReadWrite"
        else:
            paramPass = False
    else:
        paramPass = True

    my_logger.debug('\tpass ' + str(paramPass))
    return msgInterop('WriteRequirement', profile_entry, expected, permission, paramPass),\
        paramPass


def checkComparison(val, compareType, target):
    """
    Validate a given comparison option, given a value and a target set
    """
    my_logger.verbose1('Testing a comparison \n\t' + str((val, compareType, target)))
    vallist = val if isinstance(val, list) else [val]
    paramPass = False
    if compareType is None:
        my_logger.error('CompareType not available in payload')
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
        vallink = val.get('@odata.id')
        success, rf_payload, code, elapsed = callResourceURI(vallink)
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
        paramPass = val == 'DNE'
    if compareType == "Present":
        paramPass = val != 'DNE'

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
    return msgInterop('MinVersion', '{} ({})'.format(profile_entry, payload_split), '<=', version, paramPass),\
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

        compareProp = rf_payload_item.get(comparePropNames[0], 'DNE')
        if (compareProp != 'DNE') and len(comparePropNames) > 1:
            for comparePropName in comparePropNames[1:]:
                compareProp = compareProp.get(comparePropName, 'DNE')
                if compareProp == 'DNE':
                    break
        # compatability with old version, deprecate with versioning
        compareType = profile_entry.get("CompareType", profile_entry.get("Comparison"))
        return checkComparison(compareProp, compareType, profile_entry.get("CompareValues", []))[1]
    else:
        my_logger.error("Invalid Profile - No conditional given")
        raise ValueError('No conditional given for Comparison')


def validatePropertyRequirement(propResourceObj, profile_entry, rf_payload_tuple, itemname, chkCondition=False):
    """
    Validate PropertyRequirements
    """
    msgs = []
    counts = Counter()
    rf_payload_item, rf_payload = rf_payload_tuple
    if profile_entry is None or len(profile_entry) == 0:
        my_logger.debug('there are no requirements for this prop')
    else:
        my_logger.debug('propRequirement with value: ' + str(rf_payload_item if not isinstance(
            rf_payload_item, dict) else 'dict'))

    # Check the conditional requirements first or the requirements won't apply correctly against
    # a list.
    if "ConditionalRequirements" in profile_entry:
        innerList = profile_entry["ConditionalRequirements"]
        for item in innerList:
            try:
                if checkConditionalRequirement(propResourceObj, item, rf_payload_tuple):
                    my_logger.info("\tCondition DOES apply")
                    conditionalMsgs, conditionalCounts = validatePropertyRequirement(
                        propResourceObj, item, rf_payload_tuple, itemname, chkCondition = True)
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
    if isinstance(rf_payload_item, list):
        my_logger.debug("inside of a list: " + itemname)
        if "MinCount" in profile_entry:
            msg, success = validateMinCount(rf_payload_item, profile_entry["MinCount"],
                                rf_payload[0].get(itemname.split('.')[-1] + '@odata.count', 0))
            if not success:
                my_logger.error("MinCount failed")
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
        for k, v in profile_entry.get('PropertyRequirements', {}).items():
            # default to AnyOf if Comparison is not present but Values is
            comparisonValue = v.get("Comparison", "AnyOf") if v.get("Values") is not None else None
            if comparisonValue in ["AllOf", "AnyOf"]:
                msg, success = (checkComparison([val.get(k, 'DNE') for val in rf_payload_item],
                                    comparisonValue, v["Values"]))
                msgs.append(msg)
                msg.name = itemname + '.' + msg.name
        cnt = 0
        for item in rf_payload_item:
            listmsgs, listcounts = validatePropertyRequirement(
                propResourceObj, profile_entry, (item, rf_payload), itemname + '#' + str(cnt))
            counts.update(listcounts)
            msgs.extend(listmsgs)
            cnt += 1

    else:
        # consider requirement before anything else
        # problem: if dne, skip?

        # Read Requirement is default mandatory if not present
        msg, success = validateRequirement(profile_entry.get('ReadRequirement', 'Mandatory'), rf_payload_item, parent_object_tuple=rf_payload)
        msgs.append(msg)
        msg.name = itemname + '.' + msg.name

        if "WriteRequirement" in profile_entry:
            msg, success = validateWriteRequirement(propResourceObj, profile_entry["WriteRequirement"], itemname)
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            if not success:
                my_logger.error("WriteRequirement failed")
        if "MinSupportValues" in profile_entry:
            msg, success = validateSupportedValues(
                    profile_entry["MinSupportValues"],
                    rf_payload[0].get(itemname.split('.')[-1] + '@Redfish.AllowableValues', []))
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            if not success:
                my_logger.error("MinSupportValues failed")
        if "Comparison" in profile_entry and not chkCondition and\
                profile_entry["Comparison"] not in ["AnyOf", "AllOf"]:
            msg, success = checkComparison(rf_payload_item,
                    profile_entry["Comparison"], profile_entry.get("Values",[]))
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            if not success:
                my_logger.error("Comparison failed")
        if "PropertyRequirements" in profile_entry:
            innerDict = profile_entry["PropertyRequirements"]
            if isinstance(rf_payload_item, dict):
                for item in innerDict:
                    my_logger.debug('inside complex ' + itemname + '.' + item)
                    complexMsgs, complexCounts = validatePropertyRequirement(
                        propResourceObj, innerDict[item], (rf_payload_item.get(item, 'DNE'), rf_payload_tuple), item)
                    msgs.extend(complexMsgs)
                    counts.update(complexCounts)
            else:
                my_logger.info('complex {} is missing or not a dictionary'.format(itemname))
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
        msg.success = sEnum.PASS if success else sEnum.FAIL

    propDoesNotExist = (rf_payload_item == 'DNE')
    if propDoesNotExist:
        return msgs, counts
    if "@Redfish.ActionInfo" in rf_payload_item:
        vallink = rf_payload_item['@Redfish.ActionInfo']
        success, rf_payload_action, code, elapsed = callResourceURI(vallink)
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
                values_array = rf_payload_item.get(str(k) + '@Redfish.AllowableValues', 'DNE')
            if values_array == 'DNE':
                my_logger.warning('\tNo such ActionInfo exists for this Action, and no AllowableValues exists.  Cannot validate the following parameters: {}'.format(k))
                msg = msgInterop('', item, '-', '-', sEnum.WARN)
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
                        msg.success = sEnum.WARN
                    elif not success:
                        my_logger.warning('\tRecommended parameters do not all exist, but are not Mandatory')
                        msg.success = sEnum.PASS

                    msgs.append(msg)
                    msg.name = "{}.{}.{}".format(actionname, k, msg.name)
    # consider requirement before anything else, what if action
    # if the action doesn't exist, you can't check parameters
    # if it doesn't exist, what should not be checked for action
    return msgs, counts

def compareRedfishURI(expected_uris, uri, my_id):
    success = False
    if expected_uris is not None:
        regex = re.compile(r"{.*?}")
        for e in expected_uris:
            e_left, e_right = tuple(e.rsplit('/', 1))
            _uri_left, uri_right = tuple(uri.rsplit('/', 1))
            e_left = regex.sub('[a-zA-Z0-9_.-]+', e_left)
            if regex.match(e_right):
                if my_id is None:
                    my_logger.warning('No Id provided by payload')
                e_right = str(my_id)
            e_compare_to = '/'.join([e_left, e_right])
            if re.fullmatch(e_compare_to, uri) is not None:
                success = True
                break
    else:
        success = True
    return success

def checkInteropURI(r_obj, profile_entry):
    """
    Checks if the profile's URI applies to the particular resource
    """
    my_logger.debug('Testing URI \n\t' + str((r_obj.uri, profile_entry)))

    my_id, my_uri = r_obj.jsondata.get('Id'), r_obj.uri
    return compareRedfishURI(profile_entry, my_uri, my_id)

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
        # problem, unlisted in 0.9.9a
        innerDict = interop_profile["PropertyRequirements"]
        for item in innerDict:
            # vmsg, isvalid = isPropertyValid(item, propResourceObj)
            # if not isvalid:
            #     msgs.append(vmsg)
            #     vmsg.name = '{}.{}'.format(item, vmsg.name)
            #     counts['errorProfileValidityError'] += 1
            #     continue
            my_logger.info('### Validating PropertyRequirements for {}'.format(item))
            pmsgs, pcounts = validatePropertyRequirement(
                propResourceObj, innerDict[item], (rf_payload.get(item, 'DNE'), rf_payload_tuple), item)
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
                actionName, 'DNE'), rf_payloadInnerTuple), actionName)
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

    for item in msgs:
        if item.success == sEnum.WARN:
            counts['warn'] += 1
        elif item.success == sEnum.PASS:
            counts['pass'] += 1
        elif item.success == sEnum.FAIL:
            counts['fail.{}'.format(item.name)] += 1
        counts['totaltests'] += 1
    return msgs, counts
