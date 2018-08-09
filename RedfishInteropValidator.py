
# Copyright Notice:
# Copyright 2016 Distributed Management Task Force, Inc. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

import io
import os
import sys
import re
from datetime import datetime
from collections import Counter, OrderedDict
import logging
import json
import traverseService as rst
import jsonschema
import argparse
from enum import Enum
from io import StringIO

from commonProfile import getProfiles, checkProfileAgainstSchema
from traverseService import AuthenticationError
from tohtml import renderHtml, writeHtml

rsvLogger = rst.getLogger()

config = {'WarnRecommended': False}

VERBO_NUM = 15
logging.addLevelName(VERBO_NUM, "VERBO")
def verboseout(self, message, *args, **kws):
    if self.isEnabledFor(VERBO_NUM):
        self._log(VERBO_NUM, message, args, **kws)
logging.Logger.verboseout = verboseout

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
    if compareType == "Absent":
        paramPass = val == 'DNE'
    if compareType == "Present":
        paramPass = val != 'DNE'
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


def validateMinVersion(fulltype, entry):
    """
    Checks for the minimum version of a resource's type
    """
    fulltype = fulltype.replace('#', '')
    rsvLogger.info('Testing minVersion \n\t' + str((fulltype, entry)))
    # If fulltype doesn't contain version as is, try it as v#_#_#
    versionSplit = entry.split('.')
    versionNew = 'v'
    for x in versionSplit:
        versionNew = versionNew + x + '_'
    versionNew = versionNew[:-1]
    # get version from payload
    v_payload = rst.getNamespace(fulltype).split('.', 1)[-1]
    # use string comparison, given version numbering is accurate to regex
    paramPass = v_payload >= (versionNew if 'v' in v_payload else entry)
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNo Pass')
    return msgInterop('MinVersion', '{} ({})'.format(entry, versionNew), '<=', fulltype, paramPass),\
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
        while comparePropName not in decodeditem and decoded is not None:
            decodeditem, decoded = decoded
        compareProp = decodeditem.get(comparePropName, 'DNE')
        return checkComparison(compareProp, entry["Comparison"], entry.get("CompareValues", []))[1]


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
                rsvLogger.info('complex {} is missing or not a dictionary'.format(itemname + '.' + item, None))
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

    rsvLogger.addHandler(errh)  # Printout FORMAT
    rsvLogger.addHandler(warnh)  # Printout FORMAT

    yield

    rsvLogger.removeHandler(errh)  # Printout FORMAT
    rsvLogger.removeHandler(warnh)  # Printout FORMAT
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
    success = True

    results[uriName] = {'uri':URI, 'success':False, 'counts':counts,\
            'messages':messages, 'errors':'', 'warns': '',\
            'rtime':'', 'context':'', 'fulltype':''}

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
        rsvLogger.error(str(URI) + ': payload error, @odata property non-conformant',)  # Printout FORMAT

    # Generate dictionary of property info
    try:
        propResourceObj = rst.createResourceObject(
            uriName, URI, expectedJson, expectedType, expectedSchema, parent)
        if not propResourceObj:
            counts['problemResource'] += 1
            results[uriName]['warns'], results[uriName]['errors'] = next(lc)
            return False, counts, results, None, None
    except AuthenticationError as e:
        raise  # re-raise exception
    except Exception as e:
        rsvLogger.exception("")  # Printout FORMAT
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

    rsvLogger.info("\t Type (%s), GET SUCCESS (time: %s)", propResourceObj.typeobj.stype, propResourceObj.rtime)  # Printout FORMAT

    uriName, SchemaFullType, jsondata = propResourceObj.name, propResourceObj.typeobj.fulltype, propResourceObj.jsondata
    SchemaNamespace, SchemaType = rst.getNamespace(
        SchemaFullType), rst.getType(SchemaFullType)

    objRes = profile.get('Resources')

    if SchemaType not in objRes:
        rsvLogger.info(
                '\nNo Such Type in sample {} {}.{}, skipping'.format(URI, SchemaNamespace, SchemaType))
    else:
        rsvLogger.info("\n*** %s, %s", uriName, URI)
        rsvLogger.debug("\n*** %s, %s, %s", expectedType,
                        expectedSchema is not None, expectedJson is not None)
        objRes = objRes.get(SchemaType)
        rsvLogger.info(SchemaType)
        try:
            propMessages, propCounts = validateInteropResource(
                propResourceObj, objRes, jsondata)
            messages = messages.extend(propMessages)
            counts.update(propCounts)
        except Exception as ex:
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
    rsuccess = True
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
            msg, mpss = validateMinVersion(thisobj.jsondata.get("RedfishVersion", "0"), serviceVersion)
            rmessages.append(msg)

        currentLinks = [(l, links[l], thisobj) for l in links]
        while len(currentLinks) > 0:
            newLinks = list()
            for linkName, link, parent in currentLinks:
                if refLinks is not currentLinks and ('Links' in linkName.split('.', 1)[0] or 'RelatedItem' in linkName.split('.', 1)[0] or 'Redundancy' in linkName.split('.', 1)[0]):
                    refLinks.append((linkName, link, parent))
                    continue

                linkURI, autoExpand, linkType, linkSchema, innerJson = link

                if linkURI in allLinks or linkType == 'Resource.Item':
                    continue

                print('PARENT', parent.uri)
                if autoExpand and linkType is not None:
                    linkSuccess, linkCounts, linkResults, innerLinks, linkobj = \
                        validateSingleURI(linkURI, profile, "{} -> {}".format(uriName, linkName), linkType, linkSchema, innerJson, parent=parent)
                else:
                    linkSuccess, linkCounts, linkResults, innerLinks, linkobj = \
                        validateSingleURI(linkURI, profile, "{} -> {}".format(uriName, linkName), linkType, linkSchema, parent=parent)

                allLinks.add(linkURI)

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
                    msg, pss = validateRequirement(req, None)
                    if pss and objRes[SchemaType].get('mark', False) == False:
                        rmessages.append(msg)
                        msg.name = SchemaType + '.' + msg.name
                        objRes[SchemaType]['mark'] = True

                    if "ConditionalRequirements" in objRes[SchemaType]:
                        innerList = objRes[SchemaType]["ConditionalRequirements"]
                        newList = list()
                        for condreq in innerList:
                            condtrue = checkConditionalRequirement(linkobj, condreq, (linkobj.jsondata, None), None)
                            if condtrue:
                                msg, cpss = validateRequirement(condreq.get("ReadRequirement", "Mandatory"), None)
                                if cpss:
                                    rmessages.append(msg)
                                    msg.name = SchemaType + '.Conditional.' + msg.name
                                else:
                                    newList.append(condreq)
                            else:
                                newList.append(condreq)
                        objRes[SchemaType]["ConditionalRequirements"] = newList

            currentLinks = newLinks
            if len(currentLinks) == 0 and len(refLinks) > 0:
                refLinks = OrderedDict()
                currentLinks = refLinks

    # interop service level checks
    finalResults = OrderedDict()
    for left in objRes:
        resultEnum = sEnum.FAIL
        if URI != "/redfish/v1":
            resultEnum = sEnum.WARN
            traverseLogger.info("We are not validating root, warn only")
        if not objRes[left].get('mark', False):
            req = objRes[left].get("ReadRequirement", "Mandatory")
            rmessages.append(
                    msgInterop(left + '.ReadRequirement', req, 'Must Exist' if req == "Mandatory" else 'Any', 'DNE', resultEnum))
        if "ConditionalRequirements" in objRes[left]:
            innerList = objRes[left]["ConditionalRequirements"]
            for condreq in innerList:
                req = condreq.get("ReadRequirement", "Mandatory")
                rmessages.append(
                    msgInterop(left + '.Conditional.ReadRequirement', req, 'Must Exist' if req == "Mandatory" else 'Any', 'DNE', resultEnum))

    for item in rmessages:
        if item.success == sEnum.WARN:
            rcounts['warn'] += 1
        elif item.success == sEnum.PASS:
            rcounts['pass'] += 1
        elif item.success == sEnum.FAIL:
            rcounts['fail.{}'.format(item.name)] += 1

    finalResults['n/a'] = {'uri': "Service Level Requirements", 'success':rcounts.get('fail', 0) == 0,\
            'counts':rcounts,\
            'messages':rmessages, 'errors':rerror.getvalue(), 'warns': '',\
            'rtime':'', 'context':'', 'fulltype':''}
    for l in allLinks:
        print (l)
    finalResults.update(results)
    rerror.close()

    return validateSuccess, counts, finalResults, refLinks, thisobj


#############################################################
#########          Script starts here              ##########
#############################################################


validatorconfig = {'payloadmode': 'Default', 'payloadfilepath': None, 'logpath': './logs'}

def main(arglist=None, direct_parser=None):
    """
    Main program
    """
    argget = argparse.ArgumentParser(description='tool for testing services against an interoperability profile')

    # config
    argget.add_argument('-c', '--config', type=str, help='config file (overrides other params)')

    # tool
    argget.add_argument('--schemadir', type=str, default='./SchemaFiles/metadata', help='directory for local schema files')
    argget.add_argument('--schema_pack', type=str, default='', help='Deploy DMTF schema from zip distribution, for use with --localonly (Specify url or type "latest", overwrites current schema)')
    argget.add_argument('--desc', type=str, default='No desc', help='sysdescription for identifying logs')
    argget.add_argument('--logdir', type=str, default='./logs', help='directory for log files')
    argget.add_argument('--payload', type=str, help='mode to validate payloads [Tree, Single, SingleFile, TreeFile] followed by resource/filepath', nargs=2)
    argget.add_argument('--sample', type=int, default=0, help='sample this number of members from large collections for validation; default is to validate all members')
    argget.add_argument('--linklimit', type=str, help='Limit the amount of links in collections, formatted TypeName:## TypeName:## ..., default LogEntry:20 ', nargs='*')
    argget.add_argument('-v', action='store_true', help='verbose log output to stdout')
    argget.add_argument('--debug_logging', action="store_const", const=logging.DEBUG, default=logging.INFO,
            help='Output debug statements to text log, otherwise it only uses INFO')
    argget.add_argument('--verbose_checks', action="store_const", const=VERBO_NUM, default=logging.INFO,
            help='Show all checks in logging')
    argget.add_argument('--nooemcheck', action='store_true', help='Don\'t check OEM items')

    # service
    argget.add_argument('-i', '--ip', type=str, help='ip to test on [host:port]')
    argget.add_argument('-u', '--user', default='', type=str, help='user for basic auth')
    argget.add_argument('-p', '--passwd', default='', type=str, help='pass for basic auth')
    argget.add_argument('--timeout', type=int, default=30, help='requests timeout in seconds')
    argget.add_argument('--nochkcert', action='store_true', help='ignore check for certificate')
    argget.add_argument('--nossl', action='store_true', help='use http instead of https')
    argget.add_argument('--forceauth', action='store_true', help='force authentication on unsecure connections')
    argget.add_argument('--authtype', type=str, default='Basic', help='authorization type (None|Basic|Session|Token)')
    argget.add_argument('--localonly', action='store_true', help='only use locally stored schema on your harddrive')
    argget.add_argument('--service', action='store_true', help='only use uris within the service')
    argget.add_argument('--suffix', type=str, default='_v1.xml', help='suffix of local schema files (for version differences)')
    argget.add_argument('--ca_bundle', default="", type=str, help='path to Certificate Authority bundle file or directory')
    argget.add_argument('--token', default="", type=str, help='bearer token for authtype Token')
    argget.add_argument('--http_proxy', type=str, default='', help='URL for the HTTP proxy')
    argget.add_argument('--https_proxy', type=str, default='', help='URL for the HTTPS proxy')
    argget.add_argument('--cache', type=str, help='cache mode [Off, Fallback, Prefer] followed by directory', nargs=2)

    # Config information unique to Interop Validator
    argget.add_argument('profile', type=str, default='sample.json', help='interop profile with which to validate service against')
    argget.add_argument('--schema', type=str, default=None, help='schema with which to validate interop profile against')
    argget.add_argument('--warnrecommended', action='store_true', help='warn on recommended instead of pass')

    args = argget.parse_args(arglist)

    # set up config
    if direct_parser is not None:
        try:
            cdict = rst.convertConfigParserToDict(direct_parser)
            rst.setConfig(cdict)
        except Exception as ex:
            rsvLogger.exception("Something went wrong")  # Printout FORMAT
            return 1, None, 'Config Parser Exception'
    elif args.config is None and args.ip is None:
        rsvLogger.info('No ip or config specified.')
        argget.print_help()
        return 1, None, 'Config Incomplete'
    else:
        try:
            rst.setByArgparse(args)
        except Exception:
            rsvLogger.exception("Something went wrong")  # Printout FORMAT
            return 1, None, 'Config Exception'

    config = rst.config

    # Set interop config items
    config['WarnRecommended'] = rst.config.get('warnrecommended', args.warnrecommended)
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
    fh = logging.FileHandler(datetime.strftime(startTick, os.path.join(logpath, "ConformanceLog_%m_%d_%Y_%H%M%S.txt")))
    fh.setLevel(min(args.debug_logging, args.verbose_checks))
    fh.setFormatter(fmt)
    rsvLogger.addHandler(fh)  # Printout FORMAT

    # Then start service
    try:
        currentService = rst.startService()
    except Exception as ex:
        rsvLogger.error("Service could not be started: {}".format(ex))  # Printout FORMAT
        return 1, None, 'Service Exception'

    metadata = currentService.metadata
    sysDescription, ConfigURI = (config['systeminfo'], config['targetip'])

    # start printing
    rsvLogger.info('ConfigURI: ' + ConfigURI)
    rsvLogger.info('System Info: ' + sysDescription)  # Printout FORMAT
    rsvLogger.info('\n'.join(
        ['{}: {}'.format(x, config[x]) for x in sorted(list(config.keys() - set(['systeminfo', 'targetip', 'password', 'description'])))]))
    rsvLogger.info('Start time: ' + startTick.strftime('%x - %X'))  # Printout FORMAT

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
            success, counts, resultsNew, xlinks, topobj = validateSingleURI(rst.config.get('payloadfilepath'), 'Target', profile, expectedJson=jsonData)
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
                else:
                    newKey = profileName + '...' + key
                    input(newKey)
                    results[newKey] = resultsNew[key]
            #resultsNew = {profileName+key: resultsNew[key] for key in resultsNew if key in results}
            #results.update(resultsNew)

    finalCounts = Counter()
    nowTick = datetime.now()
    rsvLogger.info('Elapsed time: {}'.format(str(nowTick-startTick).rsplit('.', 1)[0]))  # Printout FORMAT

    finalCounts.update(metadata.get_counter())
    for item in results:
        innerCounts = results[item]['counts']

        # detect if there are error messages for this resource, but no failure counts; if so, add one to the innerCounts
        counters_all_pass = True
        for countType in sorted(innerCounts.keys()):
            if any(x in countType for x in ['problem', 'fail', 'bad', 'exception']):
                counters_all_pass = False
                break
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

    tool_version = '0.0'

    html_str = renderHtml(results, finalCounts, tool_version, startTick, nowTick)

    lastResultsPage = datetime.strftime(startTick, os.path.join(logpath, "ConformanceHtmlLog_%m_%d_%Y_%H%M%S.html"))

    writeHtml(html_str, lastResultsPage)

    success = success and not (fails > 0)
    rsvLogger.info(finalCounts)

    if not success:
        rsvLogger.info("Validation has failed: {} problems found".format(fails))
    else:
        rsvLogger.info("Validation has succeeded.")
        status_code = 0

    return status_code, lastResultsPage, 'Validation done'

    """
    rsvLogger.info(len(results))
    for cnt, item in enumerate(results):
        printPayload = False
        innerCounts = results[item][2]
        finalCounts.update(innerCounts)
        if results[item][3] is not None and len(results[item][3]) == 0:
           continue
        htmlStr += '<tr><td class="titlerow"><table class="titletable"><tr>'
        htmlStr += '<td class="title" style="width:40%"><div>{}</div>\
                <div class="button warn" onClick="document.getElementById(\'resNum{}\').classList.toggle(\'resultsShow\');">Show results</div>\
                </td>'.format(results[item][0], cnt, cnt)
        htmlStr += '<td class="titlesub log" style="width:30%"><div><b>URI:</b> {}</div><div><b>XML:</b> {}</div><div><b>type:</b> {}</div></td>'.format(item, results[item][5], results[item][6])
        htmlStr += '<td style="width:10%"' + \
            ('class="pass"> GET Success' if results[item]
             [1] else 'class="fail"> GET Failure') + '</td>'
        htmlStr += '<td style="width:10%">'

        for countType in sorted(innerCounts.keys()):
            if innerCounts.get(countType) == 0:
                continue
            if 'fail' in countType or 'exception' in countType:
                rsvLogger.error('{} {} errors in {}'.format(innerCounts[countType], countType, results[item][0].split(' ')[0]))
            innerCounts[countType] += 0
            htmlStr += '<div {style}>{p}: {q}</div>'.format(
                    p=countType,
                    q=innerCounts.get(countType, 0),
                    style='class="fail log"' if 'fail' in countType or 'exception' in countType else 'class="warn log"' if 'warn' in countType.lower() else 'class=log')
        htmlStr += '</td></tr>'
        htmlStr += '</table></td></tr>'
        htmlStr += '<tr><td class="results" id=\'resNum{}\'><table><tr><td><table><tr><th style="width:15%"> Name</th> <th>Entry Value</th> <th>must be</th> <th>Service Value</th> <th style="width:10%">Success</th> <tr>'.format(cnt)
        if results[item][3] is not None:
            for i in results[item][3]:
                htmlStr += '<tr>'
                htmlStr += '<td>' + str(i.name) + '</td>'
                htmlStr += '<td>' + str(i.entry) + '</td>'
                htmlStr += '<td>' + str(i.expected) + '</td>'
                htmlStr += '<td>' + str(i.actual) + '</td>'
                htmlStr += '<td class="{} center">{}</td>'.format(str(i.success.value).lower(), str(i.success.value))
                htmlStr += '</tr>'
        htmlStr += '</table></td></tr>'
        if results[item][4] is not None:
            htmlStr += '<tr><td class="fail log">' + str(results[item][4].getvalue()).replace('\n', '<br />') + '</td></tr>'
        htmlStr += "<tr><td><details><summary>Payload</summary>\
            <p class='log'>{}</p>\
            </details></td></tr></table></td></tr>".format(json.dumps(results[item][7],
                indent=4, separators=(',', ': ')) if len(results[item]) >= 8 else "n/a")

    htmlStr += '</table></body></html>'

    htmlStrTotal = '<tr><td><div>Final counts: '
    for countType in sorted(finalCounts.keys()):
        if finalCounts.get(countType) == 0:
            continue
        htmlStrTotal += '{p}: {q},   '.format(p=countType, q=finalCounts.get(countType, 0))
    htmlStrTotal += '</div><div class="button warn" onClick="arr = document.getElementsByClassName(\'results\'); for (var i = 0; i < arr.length; i++){arr[i].className = \'results resultsShow\'};">Expand All</div>'
    htmlStrTotal += '</div><div class="button fail" onClick="arr = document.getElementsByClassName(\'results\'); for (var i = 0; i < arr.length; i++){arr[i].className = \'results\'};">Collapse All</div>'

    htmlPage = htmlStrTop + htmlStrBodyHeader + htmlStrTotal + htmlStr

    with open(datetime.strftime(startTick, os.path.join(logpath, "ConformanceHtmlLog_%m_%d_%Y_%H%M%S.html")), 'w') as f:
        f.write(htmlPage)
    """

    fails = 0
    for key in finalCounts:
        if 'problem' in key or 'fail' in key or 'exception' in key:
            fails += finalCounts[key]

    success = success and not (fails > 0)
    rsvLogger.info(finalCounts)

    if not success:
        rsvLogger.info("Validation has failed: %d problems found", fails)
    else:
        rsvLogger.info("Validation has succeeded.")
        status_code = 0

    return status_code


if __name__ == '__main__':
    status_code, lastResultsPage, exit_string = main()
    sys.exit(status_code)
