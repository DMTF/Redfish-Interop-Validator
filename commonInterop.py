
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

import re
import traverseService as rst
from commonRedfish import compareRedfishURI
from enum import Enum
from collections import Counter

rsvLogger = rst.getLogger()

config = {'WarnRecommended': False, 'WriteCheck': False}


class sEnum(Enum):
    FAIL = 'FAIL'
    PASS = 'PASS'
    WARN = 'WARN'


class msgInterop:
    def __init__(self, name, entry, expected, actual, success):
        self.name = name
        self.entry = entry
        self.expected = expected
        self.actual = actual
        if isinstance(success, bool):
            self.success = sEnum.PASS if success else sEnum.FAIL
        else:
            self.success = success
        self.parent = None


def validateRequirement(entry, decodeditem, conditional=False):
    """
    Validates Requirement entry
    """
    propDoesNotExist = (decodeditem == 'DNE')
    rsvLogger.info('Testing ReadRequirement \n\texpected:' + str(entry) + ', exists: ' + str(not propDoesNotExist))
    # If we're not mandatory, pass automatically, else fail
    # However, we have other entries "IfImplemented" and "Conditional"
    # note: Mandatory is default!! if present in the profile.  Make sure this is made sure.
    originalentry = entry
    if entry == "IfImplemented" or (entry == "Conditional" and conditional):
        entry = "Mandatory"
    paramPass = not entry == "Mandatory" or \
        entry == "Mandatory" and not propDoesNotExist
    if entry == "Recommended" and propDoesNotExist:
        rsvLogger.info('\tItem is recommended but does not exist')
        if config['WarnRecommended']:
            rsvLogger.error('\tItem is recommended but does not exist, escalating to WARN')
            paramPass = sEnum.WARN

    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNoPass')
    return msgInterop('ReadRequirement', originalentry, 'Must Exist' if entry == "Mandatory" else 'Any', 'Exists' if not propDoesNotExist else 'DNE', paramPass),\
        paramPass


def isPropertyValid(profilePropName, rObj):
    for prop in rObj.getResourceProperties():
        if profilePropName == prop.propChild:
            return None, True
    rsvLogger.error('{} - Does not exist in ResourceType Schema, please consult profile provided'.format(profilePropName))
    return msgInterop('PropertyValidity', profilePropName, 'Should Exist', 'in ResourceType Schema', False), False


def validateMinCount(alist, length, annotation=0):
    """
    Validates Mincount annotation
    """
    rsvLogger.info('Testing minCount \n\texpected:' + str(length) + ', val:' + str(annotation))
    paramPass = len(alist) >= length or annotation >= length
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNoPass')
    return msgInterop('MinCount', length, '<=', annotation if annotation > len(alist) else len(alist), paramPass),\
        paramPass


def validateSupportedValues(enumlist, annotation):
    """
    Validates SupportedVals annotation
    """
    rsvLogger.info('Testing supportedValues \n\t:' + str(enumlist) + ', exists:' + str(annotation))
    for item in enumlist:
        paramPass = item in annotation
        if not paramPass:
            break
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNoPass')
    return msgInterop('SupportedValues', enumlist, 'included in...', annotation, paramPass),\
        paramPass


def findPropItemforString(propObj, itemname):
    """
    Finds an appropriate object for an item
    """
    for prop in propObj.getResourceProperties():
        decodedName = prop.name.split(':')[-1]
        if itemname == decodedName:
            return prop
    return None


def validateWriteRequirement(propObj, entry, itemname):
    """
    Validates if a property is WriteRequirement or not
    """
    rsvLogger.info('writeable \n\t' + str(entry))
    permission = 'Read'
    expected = "OData.Permission/ReadWrite" if entry else "Any"
    if not config['WriteCheck']:
        paramPass = True
        return msgInterop('WriteRequirement', entry, expected, permission, paramPass),\
            paramPass
    if entry:
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

    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNoPass')
    return msgInterop('WriteRequirement', entry, expected, permission, paramPass),\
        paramPass


def checkComparison(val, compareType, target):
    """
    Validate a given comparison option, given a value and a target set
    """
    rsvLogger.info('Testing a comparison \n\t' + str((val, compareType, target)))
    vallist = val if isinstance(val, list) else [val]
    paramPass = False
    if compareType is None:
        rsvLogger.error('CompareType not available in payload')
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
        success, decoded, code, elapsed = rst.callResourceURI(vallink)
        if success:
            ourType = decoded.get('@odata.type')
            if ourType is not None:
                SchemaType = rst.getType(ourType)
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
        if len(target) >= 1:
            target = target[0]
        else:
            target = 'DNE'

    if target != 'DNE':
        if compareType == "Equal":
            paramPass = val == target
        if compareType == "NotEqual":
            paramPass = val != target
        if compareType == "GreaterThan":
            paramPass = val > target
        if compareType == "GreaterThanOrEqual":
            paramPass = val >= target
        if compareType == "LessThan":
            paramPass = val < target
        if compareType == "LessThanOrEqual":
            paramPass = val <= target
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNoPass')
    return msgInterop('Comparison', target, compareType, val, paramPass),\
        paramPass


def validateMembers(members, entry, annotation):
    """
    Validate an entry of Members and its count annotation
    """
    rsvLogger.info('Testing members \n\t' + str((members, entry, annotation)))
    if not validateRequirement('Mandatory', members):
        return False
    if "MinCount" in entry:
        mincount, mincountpass = validateMinCount(members, entry["MinCount"], annotation)
        mincount.name = 'MembersMinCount'
    return mincount, mincountpass


def validateMinVersion(version, entry):
    """
    Checks for the minimum version of a resource's type
    """
    rsvLogger.info('Testing minVersion \n\t' + str((version, entry)))
    # If version doesn't contain version as is, try it as v#_#_#
    entry_split = entry.split('.')
    # get version from payload
    if(re.match('#([a-zA-Z0-9_.-]*\.)+[a-zA-Z0-9_.-]*', version) is not None):
        v_payload = rst.getNamespace(version).split('.', 1)[-1]
        v_payload = v_payload.replace('v', '')
        if ('_' in v_payload):
            payload_split = v_payload.split('_')
        else:
            payload_split = v_payload.split('.')
    else:
        payload_split = version.split('.')

    paramPass = True
    print(entry_split, payload_split)
    for a, b in zip(entry_split, payload_split):
        b = 0 if b is None else b
        a = 0 if a is None else a
        if (b > a):
            break
        if (b < a):
            paramPass = False
            break

    # use string comparison, given version numbering is accurate to regex
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNo Pass')
    return msgInterop('MinVersion', '{} ({})'.format(entry, payload_split), '<=', version, paramPass),\
        paramPass


def checkConditionalRequirement(propResourceObj, entry, decodedtuple, itemname):
    """
    Returns boolean if entry's conditional is true or false
    """
    rsvLogger.info('Evaluating conditionalRequirements')
    if "SubordinateToResource" in entry:
        isSubordinate = False
        # iterate through parents via resourceObj
        # list must be reversed to work backwards
        resourceParent = propResourceObj.parent
        for expectedParent in reversed(entry["SubordinateToResource"]):
            if resourceParent is not None:
                parentType = resourceParent.typeobj.stype
                isSubordinate = parentType == expectedParent
                rsvLogger.info('\tsubordinance ' +
                               str(parentType) + ' ' + str(isSubordinate))
                resourceParent = resourceParent.parent
            else:
                rsvLogger.info('no parent')
                isSubordinate = False
        return isSubordinate
    if "CompareProperty" in entry:
        decodeditem, decoded = decodedtuple
        # find property in json payload by working backwards thru objects
        # decoded tuple is designed just for this piece, since there is
        # no parent in dictionaries
        comparePropName = entry["CompareProperty"]
        while (decodeditem is None or comparePropName not in decodeditem) and decoded is not None:
            decodeditem, decoded = decoded
        if decodeditem is None:
            rsvLogger.error('Could not acquire expected CompareProperty {}'.format(comparePropName) )
            return False
        compareProp = decodeditem.get(comparePropName, 'DNE')
        # compatability with old version, deprecate with versioning
        compareType = entry.get("CompareType", entry.get("Comparison"))
        return checkComparison(compareProp, compareType, entry.get("CompareValues", []))[1]


def validatePropertyRequirement(propResourceObj, entry, decodedtuple, itemname, chkCondition=False):
    """
    Validate PropertyRequirements
    """
    msgs = []
    counts = Counter()
    decodeditem, decoded = decodedtuple
    if entry is None or len(entry) == 0:
        rsvLogger.debug('there are no requirements for this prop')
    else:
        rsvLogger.info('propRequirement with value: ' + str(decodeditem if not isinstance(
            decodeditem, dict) else 'dict'))
    # If we're working with a list, then consider MinCount, Comparisons, then execute on each item
    # list based comparisons include AnyOf and AllOf
    if isinstance(decodeditem, list):
        rsvLogger.info("inside of a list: " + itemname)
        if "MinCount" in entry:
            msg, success = validateMinCount(decodeditem, entry["MinCount"],
                                decoded[0].get(itemname.split('.')[-1] + '@odata.count', 0))
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
        for k, v in entry.get('PropertyRequirements', {}).items():
            # default to AnyOf if Comparison is not present but Values is
            comparisonValue = v.get("Comparison", "AnyOf") if v.get("Values") is not None else None
            if comparisonValue in ["AllOf", "AnyOf"]:
                msg, success = (checkComparison([val.get(k, 'DNE') for val in decodeditem],
                                    comparisonValue, v["Values"]))
                msgs.append(msg)
                msg.name = itemname + '.' + msg.name
        cnt = 0
        for item in decodeditem:
            listmsgs, listcounts = validatePropertyRequirement(
                propResourceObj, entry, (item, decoded), itemname + '#' + str(cnt))
            counts.update(listcounts)
            msgs.extend(listmsgs)
            cnt += 1

    else:
        # consider requirement before anything else
        # problem: if dne, skip?

        # Read Requirement is default mandatory if not present
        msg, success = validateRequirement(entry.get('ReadRequirement', 'Mandatory'), decodeditem)
        msgs.append(msg)
        msg.name = itemname + '.' + msg.name

        if "WriteRequirement" in entry:
            msg, success = validateWriteRequirement(propResourceObj, entry["WriteRequirement"], itemname)
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
        if "ConditionalRequirements" in entry:
            innerList = entry["ConditionalRequirements"]
            for item in innerList:
                if checkConditionalRequirement(propResourceObj, item, decodedtuple, itemname):
                    rsvLogger.info("\tCondition DOES apply")
                    conditionalMsgs, conditionalCounts = validatePropertyRequirement(
                        propResourceObj, item, decodedtuple, itemname, chkCondition = True)
                    counts.update(conditionalCounts)
                    for item in conditionalMsgs:
                        item.name = item.name.replace('.', '.Conditional.', 1)
                    msgs.extend(conditionalMsgs)
                else:
                    rsvLogger.info("\tCondition does not apply")
        if "MinSupportValues" in entry:
            msg, success = validateSupportedValues(
                    decodeditem, entry["MinSupportValues"],
                    decoded[0].get(itemname.split('.')[-1] + '@Redfish.AllowableValues', []))
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
        if "Comparison" in entry and not chkCondition and\
                entry["Comparison"] not in ["AnyOf", "AllOf"]:
            msg, success = checkComparison(decodeditem, entry["Comparison"], entry.get("Values",[]))
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
        if "PropertyRequirements" in entry:
            innerDict = entry["PropertyRequirements"]
            if isinstance(decodeditem, dict):
                for item in innerDict:
                    rsvLogger.info('inside complex ' + itemname + '.' + item)
                    complexMsgs, complexCounts = validatePropertyRequirement(
                        propResourceObj, innerDict[item], (decodeditem.get(item, 'DNE'), decodedtuple), item)
                    msgs.extend(complexMsgs)
                    counts.update(complexCounts)
            else:
                rsvLogger.info('complex {} is missing or not a dictionary'.format(itemname))
    return msgs, counts


def validateActionRequirement(propResourceObj, entry, decodedtuple, actionname):
    """
    Validate Requirements for one action
    """
    decodeditem, decoded = decodedtuple
    counts = Counter()
    msgs = []
    rsvLogger.info('actionRequirement \n\tval: ' + str(decodeditem if not isinstance(
        decodeditem, dict) else 'dict') + ' ' + str(entry))
    if "ReadRequirement" in entry:
        # problem: if dne, skip
        msg, success = validateRequirement(entry.get('ReadRequirement', "Mandatory"), decodeditem)
        msgs.append(msg)
        msg.name = actionname + '.' + msg.name
    propDoesNotExist = (decodeditem == 'DNE')
    if propDoesNotExist:
        return msgs, counts
    # problem: if dne, skip
    if "Parameters" in entry:
        innerDict = entry["Parameters"]
        for k in innerDict:
            item = innerDict[k]
            annotation = decodeditem.get(str(k) + '@Redfish.AllowableValues', 'DNE')
            # problem: if dne, skip
            # assume mandatory
            msg, success = validateRequirement(item.get('ReadRequirement', "Mandatory"), annotation)
            msgs.append(msg)
            msg.name = actionname + '.Parameters.' + msg.name
            if annotation == 'DNE':
                continue
            if "ParameterValues" in item:
                msg, success = validateSupportedValues(
                        item["ParameterValues"], annotation)
                msgs.append(msg)
                msg.name = actionname + '.' + msg.name
            if "RecommendedValues" in item:
                msg, success = validateSupportedValues(
                        item["RecommendedValues"], annotation)
                msg.name = msg.name.replace('Supported', 'Recommended')
                if config['WarnRecommended'] and not success:
                    rsvLogger.error('\tRecommended parameters do not all exist, escalating to WARN')
                    msg.success = sEnum.WARN
                elif not success:
                    rsvLogger.error('\tRecommended parameters do not all exist, but are not Mandatory')
                    msg.success = sEnum.PASS

                msgs.append(msg)
                msg.name = actionname + '.' + msg.name
    # consider requirement before anything else, what if action
    # if the action doesn't exist, you can't check parameters
    # if it doesn't exist, what should not be checked for action
    return msgs, counts


def validateInteropURI(r_obj, entry):
    """
    Checks for the minimum version of a resource's type
    """
    rsvLogger.debug('Testing URI \n\t' + str((r_obj.uri, entry)))

    my_id, my_uri = r_obj.jsondata.get('Id'), r_obj.uri
    paramPass = compareRedfishURI(entry, my_uri, my_id)
    return msgInterop('InteropURI', '{}'.format(entry), 'Matches', my_uri, paramPass),\
        paramPass


def validateInteropResource(propResourceObj, interopDict, decoded):
    """
    Base function that validates a single Interop Resource by its entry
    """
    msgs = []
    rsvLogger.info('### Validating an InteropResource')
    rsvLogger.debug(str(interopDict))
    counts = Counter()
    # decodedtuple provides the chain of dicts containing dicts, needed for CompareProperty
    decodedtuple = (decoded, None)
    if "MinVersion" in interopDict:
        msg, success = validateMinVersion(propResourceObj.typeobj.fulltype, interopDict['MinVersion'])
        msgs.append(msg)
    if "URIs" in interopDict:
        rsvLogger.info('Validating URIs')
        msg, success = validateInteropURI(propResourceObj, interopDict['URIs'])
        msgs.append(msg)
    if "PropertyRequirements" in interopDict:
        # problem, unlisted in 0.9.9a
        innerDict = interopDict["PropertyRequirements"]
        for item in innerDict:
            vmsg, isvalid = isPropertyValid(item, propResourceObj)
            if not isvalid:
                msgs.append(vmsg)
                vmsg.name = '{}.{}'.format(item, vmsg.name)
                continue
            rsvLogger.info('### Validating PropertyRequirements for {}'.format(item))
            pmsgs, pcounts = validatePropertyRequirement(
                propResourceObj, innerDict[item], (decoded.get(item, 'DNE'), decodedtuple), item)
            rsvLogger.info(pcounts)
            counts.update(pcounts)
            msgs.extend(pmsgs)
    if "ActionRequirements" in interopDict:
        innerDict = interopDict["ActionRequirements"]
        actionsJson = decoded.get('Actions', {})
        decodedInnerTuple = (actionsJson, decodedtuple)
        for item in innerDict:
            actionName = '#' + propResourceObj.typeobj.stype + '.' + item
            rsvLogger.info(actionName)
            amsgs, acounts = validateActionRequirement(propResourceObj, innerDict[item], (actionsJson.get(
                actionName, 'DNE'), decodedInnerTuple), actionName)
            rsvLogger.info(acounts)
            counts.update(acounts)
            msgs.extend(amsgs)
    if "CreateResource" in interopDict:
        rsvLogger.info('Skipping CreateResource')
        pass
    if "DeleteResource" in interopDict:
        rsvLogger.info('Skipping DeleteResource')
        pass
    if "UpdateResource" in interopDict:
        rsvLogger.info('Skipping UpdateResource')
        pass

    for item in msgs:
        if item.success == sEnum.WARN:
            counts['warn'] += 1
        elif item.success == sEnum.PASS:
            counts['pass'] += 1
        elif item.success == sEnum.FAIL:
            counts['fail.{}'.format(item.name)] += 1
    rsvLogger.info(counts)
    return msgs, counts

