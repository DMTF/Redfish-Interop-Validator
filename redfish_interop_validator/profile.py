
# Copyright Notice:
# Copyright 2017-2024 DMTF. All rights reserved.
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


def parseProfileInclude(target_name, target_profile_info, directories, online):
    min_version = splitVersionString(target_profile_info.get('MinVersion', '1.0.0'))
    target_version = 'v{}_{}_{}'.format(*min_version)
    target_file = '{}.{}'.format(target_name, 'json')

    # get max filename
    repo = target_profile_info.get('Repository')
    if online:
        data = getProfileFromRepo(target_file, repo)
    else:
        data = None

    if data is None:
        target_list = list(getProfilesMatchingName(target_file, directories))
        if len(target_list) > 0:
            max_version = (1,0,0)
            for target_name in target_list:
                with open(target_name) as f:
                    my_profile = json.load(f)
                    my_version = splitVersionString(my_profile.get('ProfileVersion', '1.0.0'))
                    max_version = max(max_version, my_version)
                    if my_version == max_version or data is None:
                        data = my_profile
            if min_version > max_version:
                my_logger.warning('File version smaller than target MinVersion')
        else:
            my_logger.error('Could not acquire this profile {} {}'.format(target_name, repo))
            data = None

    return data


def getProfiles(profile, directories, chain=None, online=False):
    profile_includes, required_by_resource = [], []
    
    profile_name = profile.get('ProfileName')
    if chain is None:
        chain = []
    if profile_name in chain:
        my_logger.error('Suspected duplicate/cyclical import error: {} {}'.format(chain, profile_name))
        return []
    chain.append(profile_name)

    required_profiles = profile.get('RequiredProfiles')
    for target_name in required_profiles:
        target_profile_info = required_profiles[target_name]
        print(target_name)

        profile_data = parseProfileInclude(target_name, target_profile_info, directories, online)

        if profile_data:
            profile_includes.append(profile_data)

            inner_includes, inner_reqs = getProfiles(profile_data, directories, chain)
            profile_includes.extend(inner_includes)
            required_by_resource.extend(inner_reqs)

    return profile_includes, required_by_resource
