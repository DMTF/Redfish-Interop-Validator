
# Copyright Notice:
# Copyright 2016 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Service-Validator/LICENSE.md

import os
import re
import glob
import json
import logging

from redfish_interop_validator.redfish import splitVersionString, versionpattern

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


defaultrepository = 'http://redfish.dmtf.org/profiles'

def getProfilesMatchingName(name, directories):
    pattern = r'\.{}\.'.format(versionpattern)
    filepattern = re.compile(pattern.join(name.split('.')) + "|{}".format(name.replace('.', '\.')))
    for dirname in directories:
        for file in glob.glob(os.path.join(dirname, '*.json')):
            if filepattern.match(os.path.basename(file)):
                yield file

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


def getProfiles(profile, directories, chain=None, online=False):
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
            min_version = splitVersionString(rp.get('MinVersion', '1.0.0'))
            targetVersion = 'v{}_{}_{}'.format(*min_version)
            targetFile = '{}.{}'.format(targetName, 'json')

            # get max filename
            repo = rp.get('Repository')
            if online:
                data = getProfileFromRepo(targetFile, repo)
            else:
                data = None

            if data is None:
                targetList = list(getProfilesMatchingName(targetFile, directories))
                if len(targetList) > 0:
                    max_version = (1,0,0)
                    for item in targetList:
                        with open(item) as f:
                            my_profile = json.load(f)
                            my_version = splitVersionString(my_profile.get('ProfileVersion', '1.0.0'))
                            max_version = max(max_version, my_version)
                            if my_version == max_version or data == None:
                                data = my_profile
                    if min_version > max_version:
                        my_logger.warning('File version smaller than target MinVersion')
                else:
                    my_logger.error('Could not acquire this profile {} {}'.format(targetName, repo))
                    continue

            alldata.extend(getProfiles(data, directories, chain))
    return alldata
