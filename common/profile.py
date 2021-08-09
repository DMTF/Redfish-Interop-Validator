
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Service-Validator/LICENSE.md

import os
import re
import json
import logging

my_logger = logging.getLogger()
my_logger.setLevel(logging.DEBUG)

from urllib.request import urlopen

def hashProfile(profile):
    from hashlib import md5
    my_md5 = md5(json.dumps(profile, sort_keys=True).encode())
    return my_md5.hexdigest()

def checkProfileAgainstSchema(profile, schema):
    """
    Checks if a profile is conformant
    """
    # what is required in a profile? use the json schema
    import jsonschema
    try:
        jsonschema.validate(profile, schema)
    except jsonschema.ValidationError as e:
        my_logger.exception(e)
        my_logger.info('ValidationError')
        return False
    except jsonschema.SchemaError as e:
        my_logger.exception(e)
        my_logger.info('SchemaError')
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
        from collections import Mapping
        for k in merge_dct:
            if (k in dct and isinstance(dct[k], dict)
                    and isinstance(merge_dct[k], Mapping)):
                dict_merge(dct[k], merge_dct[k])
            else:
                dct[k] = merge_dct[k]

def updateWithProfile(profile, data):
    dict_merge(data, profile)
    return data

def getProfileFromRepo(profilename, repo=None):
    try:
        if repo is None:
            repo = 'http://redfish.dmtf.org/profiles'

        urlpath = urlopen(repo)
        string = urlpath.read().decode('utf-8')

        pattern = r'\.{}\.'.format(versionpattern)
        filepattern = re.compile(pattern.join(profilename.split('.')))

        filelist = filepattern.findall(string)

        profilename = None
        for filename in filelist:
            filename = filename[:-1]
            if profilename is None:
                profilename = filename
                continue
            profilename = max(profilename, filename)
        if profilename is None:
            return None

        remotefile = urlopen(repo + '/' + profilename)
        return remotefile.read()
    except Exception as e:
        print(e)
        return None


def getProfiles(profile, dirname, chain=None):
    alldata = [profile]
    if 'RequiredProfiles' not in profile:
        my_logger.debug('No such item RequiredProfiles')
    else:
        profileName = profile.get('ProfileName')
        if chain is None:
            chain = []
        if profileName in chain:
            my_logger.error('Suspected duplicate/cyclical import error: {} {}'.format(chain, profileName))
            return []
        chain.append(profileName)

        requiredProfiles = profile['RequiredProfiles']
        for item in requiredProfiles:
            targetName = item
            rp = requiredProfiles[targetName]
            targetVersionUnformatted = rp.get('MinVersion', '1.0.0')
            targetVersion = 'v{}_{}_{}'.format(*tuple(targetVersionUnformatted.split('.')))
            targetFileBlank = '{}.{}'.format(targetName, extension)
            targetFile = None

            # get max filename
            repo = rp.get('Repository')
            data = getProfileFromRepo(targetFileBlank, repo)

            if data is None:
                targetList = sorted(list(getListingVersions(targetFileBlank, dirname)))
                if len(targetList) > 0:
                    for item in targetList:
                        if targetFile is None:
                            targetFile = item
                        targetFile = max(targetFile, item)
                        fileVersion = re.search(versionpattern, targetFile).group()
                    filehandle = open(dirname + '/' + targetFile, "r")
                    data = filehandle.read()
                    filehandle.close()
                    data = json.loads(data)
                    if targetVersion > fileVersion:
                        my_logger.warn('File version smaller than target MinVersion')
                else:
                    my_logger.error('Could not acquire this profile {} {}'.format(targetName, repo))
                    continue

            alldata.extend(getProfiles(data, dirname, chain))
    return alldata

