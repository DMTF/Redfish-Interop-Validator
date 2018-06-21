
# Copyright Notice:
# Copyright 2016 Distributed Management Task Force, Inc. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Service-Validator/LICENSE.md

import jsonschema
import os
import re
import json
import collections

import traverseService as rst
rsvLogger = rst.getLogger()

def checkProfileAgainstSchema(profile, schema):
    """
    Checks if a profile is conformant
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


extension = 'json'
versionpattern = 'v[0-9]_[0-9]_[0-9]'
defaultrepository = 'http://redfish.dmtf.org/profiles' 

def getListingVersions(filename, dirname):
    pattern = '\.' + versionpattern + '\.'
    filepattern = re.compile(pattern.join(filename.split('.')))
    for item in os.listdir(dirname):
        if filepattern.match(item):
            yield item

def dict_merge(dct, merge_dct):
        """
        https://gist.github.com/angstwad/bf22d1822c38a92ec0a9 modified
        Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
        updating only top-level keys, dict_merge recurses down into dicts nested
        to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
        ``dct``.
        :param dct: dict onto which the merge is executed
        :param merge_dct: dct merged into dct
        :return: None
        """
        for k in merge_dct:
            if (k in dct and isinstance(dct[k], dict)
                    and isinstance(merge_dct[k], collections.Mapping)):
                dict_merge(dct[k], merge_dct[k])
            else:
                dct[k] = merge_dct[k]

def updateWithProfile(profile, data): 
    dict_merge(data, profile)
    return data

def getProfileFromRepo(profilename, repo=None):
    if repo is None:
        repo = 'http://redfish.dmtf.org/profiles'
    success, data, status, elapsed = rst.callResourceURI(repo + '/' + profilename)
    if success:
        return data



def getProfiles(profile, dirname, chain=None):
    alldata = [profile]
    if 'RequiredProfiles' not in profile:
        rsvLogger.debug('No such item RequiredProfiles')
    else:
        profileName = profile.get('ProfileName')
        if chain is None:
            chain = []
        if profileName in chain:
            rsvLogger.error('Suspected duplicate/cyclical import error: {} {}'.format(chain, profileName))
            return []
        chain.append(profileName)

        requiredProfiles = profile['RequiredProfiles']
        for item in requiredProfiles:
            targetName = item  
            rp = requiredProfiles[targetName]
            targetVersionUnformatted = rp.get('MinVersion', '1.0.0')
            targetVersion = 'v{}_{}_{}'.format(*tuple(targetVersionUnformatted.split('.')))
            targetFileBlank = '{}.{}'.format(targetName, extension)
            targetFile = targetFileBlank.replace('.', '.{}.'.format(targetVersion))

            # get max filename
            targetList = sorted(list(getListingVersions(targetFileBlank, dirname)))
            repo = rp.get('Repository')
            data = getProfileFromRepo(targetFile, repo) 

            if data is None:
                if len(targetList) > 0:
                    for item in targetList: 
                        fileVersion = re.search(versionpattern, item).group()
                        targetFile = max(targetFile, item)
                    filehandle = open(dirname + '/' + targetFile, "r")
                    data = filehandle.read()
                    filehandle.close()
                    data = json.loads(data)
                else:
                    rsvLogger.error('Could not acquire this profile {} {}'.format(targetName, repo))
                    continue

            alldata.extend(getProfiles(data, dirname, chain))
    return alldata


def combineProfile(profile, dirname, chain=None):

    data = combineProfile(data, dirname, chain=chain)
    profile = updateWithProfile(profile, data)

    return profile
