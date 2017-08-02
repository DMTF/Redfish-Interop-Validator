
# Copyright Notice:
# Copyright 2016 Distributed Management Task Force, Inc. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Service-Validator/LICENSE.md

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

rsvLogger = rst.getLogger()


def checkProfileCompliance(profile, schema):
    """
    Checks if a profile is compliant
    """
    # what is required in a profile? use the json schema
    try:
        jsonschema.validate(profile, schema)
    except jsonschema.ValidationError as e:
        rsvLogger.exception(e)
        rsvLogger.info('ValidationError')
        return False
    except jsonschema.SchemaError as e:
        rsvLogger.exception(e)
        rsvLogger.info('SchemaError')
        return False
    # consider @odata.type, with regex
    return True


class msgInterop:
    def __init__(self, name, entry, expected, actual, success):
        self.name = name
        self.entry = entry
        self.expected = expected
        self.actual = actual
        self.success = success
        self.parent = None


def validateRequirement(entry, decodeditem):
    """
    Validates Requirement entry
    """
    propDoesNotExist = (decodeditem == 'DNE')
    rsvLogger.info('ReadRequirement \n\t' + str(entry) + ' ' + str(propDoesNotExist))
    paramPass = not entry == "Mandatory" or \
        entry == "Mandatory" and not propDoesNotExist
    if entry == "Recommended" and propDoesNotExist:
        rsvLogger.warning('\tItem is recommended but does not exist')
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNonCompliant')
    return msgInterop('ReadRequirement', entry, 'Must Exist' if entry == "Mandatory" else 'Any', 'Exists' if not propDoesNotExist else 'DNE', paramPass),\
        paramPass


def validateMinCount(alist, length, annotation=0):
    """
    Validates Mincount annotation
    """
    rsvLogger.info('minCount \n\t' + str(length) + ' ' + str(annotation))
    paramPass = len(alist) >= length or annotation >= length
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNonCompliant')
    return msgInterop('MinCount', length, '<=', annotation if annotation > len(alist) else len(alist), paramPass),\
        paramPass


def validateSupportedValues(enumlist, annotation):
    """
    Validates SupportedVals annotation
    """
    rsvLogger.info('supportedValues \n\t' + str(enumlist) + ' ' + str(annotation))
    for item in enumlist:
        paramPass = item in annotation
        if not paramPass:
            break
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNonCompliant')
    return msgInterop('SupportedValues', enumlist, 'included in...', annotation, paramPass),\
        paramPass


def findPropItemforString(propObj, itemname):
    """
    Finds an appropriate object for an item
    """
    node = propObj.typeobj
    while node is not None:
        for prop in node.propList:
            decodedName = prop.name.split(':')[-1]
            if itemname == decodedName:
                return prop
        node = node.parent
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
            permission = propAttr.get('enummember', 'Read')
            paramPass = permission \
                == "OData.Permission/ReadWrite"
        else:
            paramPass = False
    else:
        paramPass = True

    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNonCompliant')
    return msgInterop('WriteRequirement', entry, expected, permission, paramPass),\
        paramPass


def checkComparison(val, compareType, target):
    """
    Validate a given comparison option, given a value and a target set
    """
    rsvLogger.info('comparison \n\t' + str((val, compareType, target)))
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
    if compareType == "Equal":
        paramPass = val == target
    if compareType == "NotEqual":
        paramPass = val != target
    if compareType == "GreaterThan":
        paramPass = val > target
    if compareType == "GreaterThanEqual":
        paramPass = val >= target
    if compareType == "LessThan":
        paramPass = val < target
    if compareType == "LessThanEqual":
        paramPass = val <= target
    if compareType == "Absent":
        paramPass = val == 'DNE'
    if compareType == "Present":
        paramPass = val != 'DNE'
    rsvLogger.info('\tpass ' + str(paramPass))
    if not paramPass:
        rsvLogger.error('\tNonCompliant')
    return msgInterop('Comparison', target, compareType, val, paramPass),\
        paramPass


def validateMembers(members, entry, annotation):
    """
    Validate an entry of Members and its count annotation
    """
    rsvLogger.info('members \n\t' + str((members, entry, annotation)))
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
    rsvLogger.info('minVersion \n\t' + str((fulltype, entry)))
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
        rsvLogger.error('\tNonCompliant')
    return msgInterop('MinVersion', '{} ({})'.format(entry, versionNew), '<=', fulltype, paramPass),\
        paramPass


def checkConditionalRequirement(propResourceObj, entry, decodedtuple, itemname):
    """
    Returns boolean if entry's conditional is true or false
    """
    rsvLogger.info('conditionalRequirements \n\t' + str(entry))
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
        return checkComparison(compareProp, entry["Comparison"], entry.get("CompareValues"))
    if "WriteRequirement" in entry:
        return validateWriteRequirement(propResourceObj, entry["WriteRequirement"], itemname)


def validatePropertyRequirement(propResourceObj, entry, decodedtuple, itemname, chkCondition=False, inlist=None):
    """
    Validate PropertyRequirements
    """
    msgs = [] 
    counts = Counter()
    decodeditem, decoded = decodedtuple
    rsvLogger.info('propRequirement \n\tval: ' + str(decodeditem if not isinstance(
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
            counts["pass"] += 1 if success else 0
            counts["failMinCountFail"] += 1 if not success else 0
        for k, v in entry.get('PropertyRequirements', {}).items():
            if "Comparison" in v and v["Comparison"] in ["AllOf", "AnyOf"]:
                msg, success = (checkComparison([val.get(k, '') for val in decodeditem],
                                    v["Comparison"], v["Values"]))
                msgs.append(msg)
                msg.name = itemname + '.' + msg.name
                counts["pass"] += 1 if success else 0
                counts["failComparisonList"] += 1 if not success else 0
        cnt = 0
        for item in decodeditem:
            listmsgs, listcounts = validatePropertyRequirement(
                propResourceObj, entry, (item, decoded), itemname + '#' + str(cnt), inlist=decodeditem)
            counts.update(listcounts)
            msgs.extend(listmsgs)
            cnt += 1

    else:
        # consider requirement before anything else
        # problem: if dne, skip?
        if "ReadRequirement" in entry:
            # problem: if dne, skip
            msg, success = validateRequirement(entry['ReadRequirement'], decodeditem)
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            counts["pass"] += 1 if success else 0
            counts["failRequirement"] += 1 if not success else 0
        if "ConditionalRequirements" in entry:
            innerDict = entry["ConditionalRequirements"]
            for item in innerDict:
                if checkConditionalRequirement(propResourceObj, item, decodedtuple, itemname):
                    conditionalMsgs, conditionalCounts = validatePropertyRequirement(
                        propResourceObj, item, decodedtuple, itemname, True)
                    counts.update(conditionalCounts)
                    msgs.extend(conditionalMsgs)
                else:
                    rsvLogger.info("Condition does not apply")
        if "WriteRequirement" in entry and not chkCondition:
            msg, success = validateWriteRequirement(propResourceObj, entry["WriteRequirement"], itemname)
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            counts["pass"] += 1 if success else 0
            counts["failWriteRequirement"] += 1 if not success else 0
        if "MinSupportValues" in entry:
            msg, success = validateSupportedValues(
                    decodeditem, entry["MinSupportValues"],
                    decoded[0].get(itemname.split('.')[-1] + '@Redfish.AllowableValues', []))
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            counts["pass"] += 1 if success else 0
            counts["failMinSupportValues"] += 1 if not success else 0
        if "Comparison" in entry and not chkCondition and \
                (inlist is None and entry["Comparison"] not in ["AnyOf", "AllOf"]):
            msg, success = checkComparison(decodeditem, entry["Comparison"], entry.get("Values",[]))
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            counts["pass"] += 1 if success else 0
            counts["failComparison"] += 1 if not success else 0
        elif "Values" in entry and not chkCondition and (inlist is None):
            msg, success = checkComparison(decodeditem, "AnyOf", entry["Values"])
            msgs.append(msg)
            msg.name = itemname + '.' + msg.name
            counts["pass"] += 1 if success else 0
            counts["failComparison"] += 1 if not success else 0
        if "PropertyRequirements" in entry:
            innerDict = entry["PropertyRequirements"]
            if isinstance(decodeditem, dict):
                for item in innerDict:
                    rsvLogger.info('inside complex ' + itemname + '.' + item)
                    complexMsgs, complexCounts = validatePropertyRequirement(
                        propResourceObj, innerDict[item], (decodeditem.get(item, 'DNE'), decodedtuple), item)
                    msgs.extend(complexMsgs)
                    counts.update(complexCounts)
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
        msg, success = validateRequirement(entry['ReadRequirement'], decodeditem)
        msgs.append(msg)
        msg.name = actionname + '.' + msg.name
        counts["pass"] += 1 if success else 0
        counts["failActionRequirement"] += 1 if not success else 0
    propDoesNotExist = (decodeditem == 'DNE')
    if propDoesNotExist:
        return msgs, counts
    # problem: if dne, skip
    if "Parameters" in entry:
        innerDict = entry["Parameters"]
        for k in innerDict:
            item = innerDict[k]
            annotation = decodeditem.get(str(k) + '@Redfish.AllowableValues', 'DNE')
            if "ReadRequirement" in entry:
                # problem: if dne, skip
                msg, success = validateRequirement(item['ReadRequirement'], annotation)
                msgs.append(msg)
                msg.name = actionname + '.' + msg.name
                counts["pass"] += 1 if success else 0
                counts["failActionRequirementParam"] += 1 if not success else 0
            if annotation == 'DNE':
                continue
            if "AllowableValues" in item:
                msg, success = validateSupportedValues(
                        item["AllowableValues"], annotation)
                msgs.append(msg)
                msg.name = actionname + '.' + msg.name
                counts["pass"] += 1 if success else 0
                counts["failActionMinSupportValues"] += 1 if not success else 0
    # consider requirement before anything else, what if action
    # if the action doesn't exist, you can't check parameters
    # if it doesn't exist, what should not be checked for action
    return msgs, counts


def validateInteropResource(propResourceObj, interopDict, decoded):
    """
    Base function that validates a single Interop Resource by its entry
    """
    msgs = []
    rsvLogger.info('interopResource \n\t' + str(interopDict))
    counts = Counter()
    decodedtuple = (decoded, None)
    if "ReadRequirement" in interopDict:
        # problem: if dne, skip
        msg, success = validateRequirement(interopDict['ReadRequirement'], None)
        msgs.append(msg)
        counts["pass"] += 1 if success else 0
        counts["failRequirement"] += 1 if not success else 0
    if "Members" in interopDict:
        # problem: if dne, skip
        members = propResourceObj.jsondata.get('Members', 'DNE')
        annotation = propResourceObj.jsondata.get('Members@odata.count', 0)
        msg, success = validateMembers(members, interopDict['Members'], annotation)
        msgs.append(msg)
        counts["pass"] += 1 if success else 0
        counts["failMembers"] += 1 if not success else 0
    if "MinVersion" in interopDict:
        msg, success = validateMinVersion(propResourceObj.typeobj.fulltype, interopDict['MinVersion'])
        msgs.append(msg)
        counts["pass"] += 1 if success else 0
        counts["failMinVersion"] += 1 if not success else 0
    if "PropertyRequirements" in interopDict:
        innerDict = interopDict["PropertyRequirements"]
        for item in innerDict:
            rsvLogger.info('\n' + item)
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

    rsvLogger.info(counts)
    return msgs, counts


def checkPayloadCompliance(uri, decoded):
    """
    checks for @odata entries and their compliance
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
            rsvLogger.error(key + "@odata item not compliant: " + decoded[key])
            success = False
        messages[key] = (decoded[key], 'odata',
                         'Exists',
                         'PASS' if paramPass else 'FAIL')
    return success, messages


def validateSingleURI(URI, profile, uriName='', expectedType=None, expectedSchema=None, expectedJson=None, parent=None):
    """
    Validates a single URI that is given, returning its ResourceObject, counts and links
    """
    # rs-assertion: 9.4.1
    # Initial startup here
    errorMessages = io.StringIO()
    fmt = logging.Formatter('%(levelname)s - %(message)s')
    errh = logging.StreamHandler(errorMessages)
    errh.setLevel(logging.ERROR)
    errh.setFormatter(fmt)

    # Start
    counts = Counter()
    results = OrderedDict()
    messages = []
    success = True

    # check for @odata mandatory stuff
    # check for version numbering problems
    # check id if its the same as URI
    # check @odata.context instead of local.  Realize that @odata is NOT a
    # "property"

    # Attempt to get a list of properties
    successGet, jsondata, status, rtime = rst.callResourceURI(URI)
    successPayload, odataMessages = checkPayloadCompliance(URI, jsondata if successGet else {})

    if not successPayload:
        counts['failPayloadError'] += 1
        rsvLogger.error(str(URI) + ':  payload error, @odata property noncompliant',)
        # rsvLogger.removeHandler(errh)
        # return False, counts, results, None, propResourceObj
    # Generate dictionary of property info

    try:
        propResourceObj = rst.ResourceObj(
            uriName, URI, expectedType, expectedSchema, expectedJson, parent)
        if not propResourceObj.initiated:
            counts['problemResource'] += 1
            success = False
            results[uriName] = (URI, success, counts, messages,
                                errorMessages, None, None)
            return False, counts, results, None, None
    except Exception as e:
        counts['exceptionResource'] += 1
        success = False
        results[uriName] = (URI, success, counts, messages,
                            errorMessages, None, None)
        return False, counts, results, None, None
    counts['passGet'] += 1
    results[uriName] = (str(URI) + ' ({}s)'.format(propResourceObj.rtime), success, counts, messages, errorMessages, propResourceObj.context, propResourceObj.typeobj.fulltype)

    uriName, SchemaFullType, jsondata = propResourceObj.name, propResourceObj.typeobj.fulltype, propResourceObj.jsondata
    SchemaNamespace, SchemaType = rst.getNamespace(
        SchemaFullType), rst.getType(SchemaFullType)

    objRes = profile.get('Resources')

    if SchemaType not in objRes:
        rsvLogger.debug(
                'No Such Type in sample ' + URI + ' ' + SchemaNamespace + '.' + SchemaType)
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
                'Could not finish compliance check on this property')
            counts['exceptionPropCompliance'] += 1
        rsvLogger.info('%s, %s\n', SchemaFullType, counts)

    # Get all links available

    rsvLogger.debug(propResourceObj.links)
    rsvLogger.removeHandler(errh)
    return True, counts, results, propResourceObj.links, propResourceObj


def validateURITree(URI, uriName, profile, expectedType=None, expectedSchema=None, expectedJson=None, parent=None, allLinks=None):
    """
    Validates a Tree of URIs, traversing from the first given
    """
    traverseLogger = rst.getLogger()

    def executeLink(linkItem, parent=None):
        linkURI, autoExpand, linkType, linkSchema, innerJson = linkItem

        if linkType is not None and autoExpand:
            returnVal = validateURITree(
                linkURI, uriName + ' -> ' + linkName, profile, linkType, linkSchema, innerJson, parent, allLinks)
        else:
            returnVal = validateURITree(
                linkURI, uriName + ' -> ' + linkName, profile, parent=parent, allLinks=allLinks)
        return returnVal

    top = allLinks is None
    if top:
        allLinks = set()
    allLinks.add(URI)
    refLinks = OrderedDict()

    validateSuccess, counts, results, links, thisobj = \
        validateSingleURI(URI, profile, uriName, expectedType,
                          expectedSchema, expectedJson, parent)
    if validateSuccess:
        for linkName in links:
            if 'Links' in linkName.split('.', 1)[0] or 'RelatedItem' in linkName.split('.', 1)[0] or 'Redundancy' in linkName.split('.', 1)[0]:
                refLinks[linkName] = links[linkName]
                continue
            if links[linkName][0] in allLinks:
                counts['repeat'] += 1
                continue

            success, linkCounts, linkResults, xlinks = executeLink(
                links[linkName], thisobj)
            refLinks.update(xlinks)
            if not success:
                counts['unvalidated'] += 1
            results.update(linkResults)

    if top:
        for linkName in refLinks:
            if refLinks[linkName][0] not in allLinks:
                traverseLogger.info('%s, %s', linkName, refLinks[linkName])
                counts['reflink'] += 1
            else:
                continue

            success, linkCounts, linkResults, xlinks = executeLink(
                refLinks[linkName], thisobj)
            if not success:
                counts['unvalidatedRef'] += 1
            results.update(linkResults)

    return validateSuccess, counts, results, refLinks

#############################################################
#########          Script starts here              ##########
#############################################################


def main(argv):
    # Set config
    argget = argparse.ArgumentParser(description='Usecase tool to check compliance to POST Boot action')
    argget.add_argument('--ip', type=str, help='ip to test on [host:port]')
    argget.add_argument('-c', '--config', type=str, help='config file (overrides other params)')
    argget.add_argument('-u', '--user', default=None, type=str, help='user for basic auth')
    argget.add_argument('-p', '--passwd', default=None, type=str, help='pass for basic auth')
    argget.add_argument('--desc', type=str, default='No desc', help='sysdescription for identifying logs')
    argget.add_argument('--dir', type=str, default='./SchemaFiles/metadata', help='directory for local schema files')
    argget.add_argument('--logdir', type=str, default='./logs', help='directory for log files')
    argget.add_argument('--timeout', type=int, default=30, help='requests timeout in seconds')
    argget.add_argument('--nochkcert', action='store_true', help='ignore check for certificate')
    argget.add_argument('--nossl', action='store_true', help='use http instead of https')
    argget.add_argument('--localonly', action='store_true', help='only use local schema')
    argget.add_argument('--authtype', type=str, default='Basic', help='authorization type (None|Basic|Session, default Basic)')
    argget.add_argument('--service', action='store_true', help='only use uris within the service')
    argget.add_argument('--suffix', type=str, default='_v1.xml', help='suffix of local schema files (for version differences)')
    argget.add_argument('profile', type=str, default='sample.json', help='interop profile with which to validate service against')
    argget.add_argument('--schema', type=str, default=None, help='schema with which to validate interop profile against')
    
    args = argget.parse_args()    
    rsvLogger = rst.getLogger()
    
    if args.config is not None:
        rst.setConfig(args.config)
        rst.isConfigSet()
    elif args.ip is not None:
        rst.setConfigNamespace(args)
        rst.isConfigSet()
    else:
        rsvLogger.info('No ip or config specified.')
        argget.print_help()
        return 1

    sysDescription, ConfigURI, chkCert, localOnly = (
        rst.sysDescription, rst.ConfigURI, rst.chkCert, rst.localOnly)
    User, SchemaLocation = rst.User, rst.SchemaLocation
    logpath = rst.LogPath

    # Logging config
    startTick = datetime.now()
    if not os.path.isdir(logpath):
        os.makedirs(logpath)
    fmt = logging.Formatter('%(levelname)s - %(message)s')
    fh = logging.FileHandler(datetime.strftime(startTick, os.path.join(logpath, "ComplianceLog_%m_%d_%Y_%H%M%S.txt")))

    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    rsvLogger.addHandler(fh)
    rsvLogger.info('System Info: ' + sysDescription)
    rsvLogger.info("RedfishServiceValidator Config details: %s", str(
        (ConfigURI, 'user:' + str(User), SchemaLocation, 'CheckCert' if chkCert else 'no CheckCert', 'localOnly' if localOnly else 'Attempt for Online Schema')))
    rsvLogger.info("Profile: {},  Schema: {}".format(args.profile, str(args.schema)))
    rsvLogger.info('Start time: ' + startTick.strftime('%x - %X'))

    profile = schema = None
    success = True
    with open(args.profile) as f:
        profile = json.loads(f.read())
        if args.schema is not None:
            with open(args.schema) as f:
                schema = json.loads(f.read())
                success = checkProfileCompliance(profile, schema)
    if not success:
        rsvLogger.info("Profile did not comply to the given schema...")
        return 1

    # Start main
    status_code = 1
    success, counts, results, xlinks = validateURITree(
        '/redfish/v1', 'ServiceRoot', profile=profile)
    nowTick = datetime.now()
    rsvLogger.info('Elapsed time: ' +
                   str(nowTick - startTick).rsplit('.', 1)[0])

    finalCounts = counts
    
    # Render html
    htmlStrTop = '<html><head><title>Compliance Test Summary</title>\
            <style>\
            .pass {background-color:#99EE99}\
            .fail {background-color:#EE9999}\
            .warn {background-color:#EEEE99}\
            .button {padding: 12px; display: inline-block}\
            .center {text-align:center;}\
            .log {text-align:left; white-space:pre-wrap; word-wrap:break-word; font-size:smaller}\
            .title {background-color:#DDDDDD; border: 1pt solid; font-height: 30px; padding: 8px}\
            .titlesub {padding: 8px}\
            .titlerow {border: 2pt solid}\
            .results {transition: visibility 0s, opacity 0.5s linear; display: none; opacity: 0}\
            .resultsShow {display: block; opacity: 1}\
            body {background-color:lightgrey; border: 1pt solid; text-align:center; margin-left:auto; margin-right:auto}\
            th {text-align:center; background-color:beige; border: 1pt solid}\
            td {text-align:left; background-color:white; border: 1pt solid; word-wrap:break-word;}\
            table {width:90%; margin: 0px auto; table-layout:fixed;}\
            .titletable {width:100%}\
            </style>\
            </head>'
    htmlStrBodyHeader = '<body><table>\
                <tr><th>##### Redfish Compliance Test Report #####</th></tr>\
                <tr><th>System: ' + ConfigURI + '</th></tr>\
                <tr><th>Description: ' + sysDescription + '</th></tr>\
                <tr><th>User: ' + str(User) + ' ###  \
                SSL Cert Check: ' + str(chkCert) + ' ###  \n\
                Local Only Schema:' + str(localOnly) + ' ###  Local Schema Location :' + SchemaLocation + '</th></tr>\
                <tr><th>Start time: ' + (startTick).strftime('%x - %X') + '</th></tr>\
                <tr><th>Run time: ' + str(nowTick-startTick).rsplit('.', 1)[0] + '</th></tr>\
                <tr><th>' + 'Profile: {},  Schema: {}'.format(args.profile, args.schema) + '</th></tr>\
                <tr><th></th></tr>'
    htmlStr = ''

    for cnt, item in enumerate(results):
        if results[item][3] is not None and len(results[item][3]) == 0:
           continue
        htmlStr += '<tr><td class="titlerow"><table class="titletable"><tr>'
        htmlStr += '<td class="title" style="width:40%"><div>{}</div>\
                <div class="button warn" onClick="document.getElementById(\'resNum{}\').classList.toggle(\'resultsShow\');">Show results</div>\
                </td>'.format(item, cnt, cnt)
        htmlStr += '<td class="titlesub log" style="width:30%"><div><b>URI:</b> {}</div><div><b>XML:</b> {}</div><div><b>type:</b> {}</div></td>'.format(results[item][0],results[item][5],results[item][6])
        htmlStr += '<td style="width:10%"' + \
            ('class="pass"> GET Success' if results[item]
             [1] else 'class="fail"> GET Failure') + '</td>'
        htmlStr += '<td style="width:10%">'

        innerCounts = results[item][2]
        finalCounts.update(innerCounts)
        for countType in sorted(innerCounts.keys()):
            if innerCounts.get(countType) == 0:
                continue
            if 'fail' in countType or 'exception' in countType:
                rsvLogger.error('{} {} errors in {}'.format(innerCounts[countType], countType, results[item][0].split(' ')[0]))
            innerCounts[countType] += 0
            htmlStr += '<div {style}>{p}: {q}</div>'.format(
                    p=countType,
                    q=innerCounts.get(countType, 0),
                    style='class="fail log"' if 'fail' in countType or 'exception' in countType else 'class=log')
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
                htmlStr += '<td>' + str(i.success) + '</td>'
                htmlStr += '</tr>'
        htmlStr += '</table></td></tr>'
        if results[item][4] is not None:
            htmlStr += '<tr><td class="fail log">' + str(results[item][4].getvalue()).replace('\n', '<br />') + '</td></tr>'
            results[item][4].close()
        htmlStr += '<tr><td>---</td></tr></table></td></tr>'

    htmlStr += '</table></body></html>'

    htmlStrTotal = '<tr><td><div>Final counts: '
    for countType in sorted(finalCounts.keys()):
        if finalCounts.get(countType) == 0:
            continue
        htmlStrTotal += '{p}: {q},   '.format(p=countType, q=finalCounts.get(countType, 0))
    htmlStrTotal += '</div><div class="button warn" onClick="arr = document.getElementsByClassName(\'results\'); for (var i = 0; i < arr.length; i++){arr[i].className = \'results resultsShow\'};">Expand All</div>'
    htmlStrTotal += '</div><div class="button fail" onClick="arr = document.getElementsByClassName(\'results\'); for (var i = 0; i < arr.length; i++){arr[i].className = \'results\'};">Collapse All</div>'

    htmlPage = htmlStrTop + htmlStrBodyHeader + htmlStrTotal + htmlStr

    with open(datetime.strftime(startTick, os.path.join(logpath, "ComplianceHtmlLog_%m_%d_%Y_%H%M%S.html")), 'w') as f:
        f.write(htmlPage)


    fails = 0
    for key in finalCounts:
        if 'fail' in key or 'exception' in key:
            fails += counts[key]

    success = success and not (fails > 0)
    rsvLogger.info(finalCounts)

    if not success:
        rsvLogger.info("Validation has failed: %d problems found", fails)
    else:
        rsvLogger.info("Validation has succeeded.")
        status_code = 0

    return status_code


if __name__ == '__main__':
    sys.exit(main(sys.argv))
