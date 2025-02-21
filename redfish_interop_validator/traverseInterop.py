# Copyright Notice:
# Copyright 2017-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Service-Validator/blob/master/LICENSE.md

import requests
import sys
import re
import os
import json
import random
from collections import OrderedDict, namedtuple
from functools import lru_cache
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse, urlunparse
from http.client import responses

from redfish_interop_validator.redfish import createContext, getNamespace, getNamespaceUnversioned, getType, navigateJsonFragment
from redfish_interop_validator.session import rfSession

traverseLogger = logging.getLogger(__name__)
my_logger = traverseLogger
currentService = None
config = {}

commonHeader = {'OData-Version': '4.0'}
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# dictionary to hold sampling notation strings for URIs
uri_sample_map = dict()

class AuthenticationError(Exception):
    """Exception used for failed basic auth or token auth"""
    def __init__(self, msg=None):
        super(AuthenticationError, self).__init__(msg)


def getLogger():
    """
    Grab logger for tools that might use this lib
    """
    return traverseLogger


def startService(config):
    """startService

    Begin service to use, sets as global

    Notes: Strip globals, turn into normal factory

    :param config: configuration of service
    :param defaulted: config options not specified by the user
    """
    global currentService
    if currentService is not None:
        currentService.close()
    currentService = rfService(config)
    config = currentService.config
    return currentService


class rfService():
    def __init__(self, my_config):
        traverseLogger.info('Setting up service...')
        global config
        config = my_config
        self.config = my_config
        # self.proxies = dict()
        self.active = False
        # Create a Session to optimize connection times
        self.session = requests.Session()

        # setup URI
        self.config['configuri'] = self.config['ip']
        self.config['usessl'] = urlparse(self.config['configuri']).scheme in ['https']
        self.config['certificatecheck'] = False
        self.config['certificatebundle'] = None
        self.config['timeout'] = 10

        # NOTE: this is a validator limitation.  maybe move this to its own config inside validateResource
        if self.config['collectionlimit']:
            total_len = len(self.config['collectionlimit']) / 2
            limit_string = ' '.join(self.config['collectionlimit'])
            limit_array = [tuple(found_item.split(' ')) for found_item in re.findall(r"[A-Za-z]+ [0-9]+", limit_string)]
            if len(limit_array) != total_len:
                raise ValueError('Collection Limit array seems malformed, use format: RESOURCE1 COUNT1 RESOURCE2 COUNT2)...')
            self.config['collectionlimit'] = {x[0]: int(x[1]) for x in limit_array}

        # httpprox = config['httpproxy']
        # httpsprox = config['httpsproxy']
        # self.proxies['http'] = httpprox if httpprox != "" else None
        # self.proxies['https'] = httpsprox if httpsprox != "" else None

        # Convert list of strings to dict
        # self.chkcertbundle = config['certificatebundle']
        # chkcertbundle = self.chkcertbundle
        # if chkcertbundle not in [None, ""] and config['certificatecheck']:
        #     if not os.path.isfile(chkcertbundle) and not os.path.isdir(chkcertbundle):
        #         self.chkcertbundle = None
        #         traverseLogger.error('ChkCertBundle is not found, defaulting to None')
        # else:
        #     config['certificatebundle'] = None

        self.currentSession = None
        if not self.config['usessl'] and not self.config['forceauth']:
            if config['username'] not in ['', None] or config['password'] not in ['', None]:
                traverseLogger.warning('Attempting to authenticate on unchecked http/https protocol is insecure, if necessary please use ForceAuth option.  Clearing auth credentials...')
                config['username'] = ''
                config['password'] = ''
        if config['authtype'].lower() == 'session':
            # certVal = chkcertbundle if ChkCert and chkcertbundle is not None else ChkCert
            # no proxy for system under test
            # self.currentSession = rfSession(config['username'], config['password'], config['configuri'], None, certVal, self.proxies)
            self.currentSession = rfSession(config['username'], config['password'], config['configuri'], None)
            self.currentSession.startSession()

        target_version = 'n/a'

        # get Version
        success, data, status, delay, _ = self.callResourceURI('/redfish/v1')
        if not success:
            traverseLogger.warning('Could not get ServiceRoot')
        else:
            if 'RedfishVersion' not in data:
                traverseLogger.warning('Could not get RedfishVersion from ServiceRoot')
            else:
                traverseLogger.info('Redfish Version of Service: {}'.format(data['RedfishVersion']))
                target_version = data['RedfishVersion']
        if target_version in ['1.0.0', 'n/a']:
            traverseLogger.warning('!!Version of target may produce issues!!')
        
        self.service_root = data

        # with Version, get default and compare to user defined values
        # default_config_target = defaultconfig_by_version.get(target_version, dict())
        # override_with = {k: default_config_target[k] for k in default_config_target if k in default_entries}
        # if len(override_with) > 0:
        #     traverseLogger.info('CONFIG: RedfishVersion {} has augmented these tool defaults {}'.format(target_version, override_with))
        # self.config.update(override_with)

        self.active = True

    def close(self):
        if self.currentSession is not None and self.currentSession.started:
            self.currentSession.killSession()
        self.active = False

    def getFromCache(URILink, CacheDir):
        CacheDir = os.path.join(CacheDir + URILink)
        payload = None
        if os.path.isfile(CacheDir):
            with open(CacheDir) as f:
                payload = f.read()
        if os.path.isfile(os.path.join(CacheDir, 'index.xml')):
            with open(os.path.join(CacheDir, 'index.xml')) as f:
                payload = f.read()
        if os.path.isfile(os.path.join(CacheDir, 'index.json')):
            with open(os.path.join(CacheDir, 'index.json')) as f:
                payload = json.loads(f.read())
            payload = navigateJsonFragment(payload, URILink)
        return payload

    @lru_cache(maxsize=128)
    def callResourceURI(self, URILink):
        """
        Makes a call to a given URI or URL

        param arg1: path to URI "/example/1", or URL "http://example.com"
        return: (success boolean, data, request status code, full response)
        """
        # rs-assertions: 6.4.1, including accept, content-type and odata-versions
        # rs-assertion: handle redirects?  and target permissions
        # rs-assertion: require no auth for serviceroot calls
        if URILink is None:
            traverseLogger.warning("This URI is empty!")
            return False, None, -1, 0, None

        config = self.config
        # proxies = self.proxies
        ConfigIP, UseSSL, AuthType, ChkCert, ChkCertBundle, timeout, Token = config['configuri'], config['usessl'], config['authtype'], \
                config['certificatecheck'], config['certificatebundle'], config['timeout'], config['token']
        # CacheMode, CacheDir = config['cachemode'], config['cachefilepath']

        scheme, netloc, path, params, query, fragment = urlparse(URILink)
        inService = scheme == '' and netloc == ''
        if inService:
            scheme, netloc, _path, __params, ___query, ____fragment = urlparse(ConfigIP)
            URLDest = urlunparse((scheme, netloc, path, params, query, fragment))
        else:
            URLDest = urlunparse((scheme, netloc, path, params, query, fragment))

        payload, statusCode, elapsed, auth, noauthchk = None, '', 0, None, True

        isXML = False
        if "$metadata" in path or ".xml" in path[:-5]:
            isXML = True
            traverseLogger.debug('Should be XML')

        ExtraHeaders = None
        if 'extrajsonheaders' in config and not isXML:
            ExtraHeaders = config['extrajsonheaders']
        elif 'extraxmlheaders' in config and isXML:
            ExtraHeaders = config['extraxmlheaders']

        # determine if we need to Auth...
        if inService:
            noauthchk = URILink in ['/redfish', '/redfish/v1', '/redfish/v1/odata'] or\
                '/redfish/v1/$metadata' in URILink

            auth = None if noauthchk else (config.get('username'), config.get('password'))
            traverseLogger.debug('dont chkauth' if noauthchk else 'chkauth')

            # if CacheMode in ["Fallback", "Prefer"]:
            #     payload = rfService.getFromCache(URILink, CacheDir)

        # if not inService and config['schema_origin'].lower() == 'service':
        #     traverseLogger.debug('Disallowed out of service URI ' + URILink)
        #     return False, None, -1, 0

        # rs-assertion: do not send auth over http
        # remove UseSSL if necessary if you require unsecure auth
        if (not UseSSL and not config['forceauth']) or not inService or AuthType != 'Basic':
            auth = None

        # only send token when we're required to chkauth, during a Session, and on Service and Secure
        headers = {}
        headers.update(commonHeader)
        if not noauthchk and inService and UseSSL:
            traverseLogger.debug('successauthchk')
            if AuthType == 'Session':
                currentSession = currentService.currentSession
                headers.update({"X-Auth-Token": currentSession.getSessionKey()})
            elif AuthType == 'Token':
                headers.update({"Authorization": "Bearer " + Token})

        if ExtraHeaders is not None:
            headers.update(ExtraHeaders)

        certVal = ChkCertBundle if ChkCert and ChkCertBundle not in [None, ""] else ChkCert

        # rs-assertion: must have application/json or application/xml
        traverseLogger.debug('callingResourceURI {}with authtype {} and ssl {}: {} {}'.format(
            'out of service ' if not inService else '', AuthType, UseSSL, URILink, headers))
        response = None
        try:
            if payload is not None: # and CacheMode == 'Prefer':
                return True, payload, -1, 0, response
            response = self.session.get(URLDest, headers=headers, auth=auth, verify=certVal, timeout=timeout)  # only proxy non-service
            expCode = [200]
            elapsed = response.elapsed.total_seconds()
            statusCode = response.status_code
            traverseLogger.debug('{}, {}, {},\nTIME ELAPSED: {}'.format(statusCode, expCode, response.headers, elapsed))
            if statusCode in expCode:
                contenttype = response.headers.get('content-type')
                if contenttype is None:
                    traverseLogger.error("Content-type not found in header: {}".format(URILink))
                    contenttype = ''
                if 'application/json' in contenttype:
                    traverseLogger.debug("This is a JSON response")
                    decoded = response.json(object_pairs_hook=OrderedDict)
                    # navigate fragment
                    decoded = navigateJsonFragment(decoded, URILink)
                    if decoded is None:
                        traverseLogger.error("The JSON pointer in the fragment of this URI is not constructed properly: {}".format(URILink))
                elif 'application/xml' in contenttype:
                    decoded = response.text
                elif 'text/xml' in contenttype:
                    # non-service schemas can use "text/xml" Content-Type
                    if inService:
                        traverseLogger.warning("Incorrect content type 'text/xml' for file within service {}".format(URILink))
                    decoded = response.text
                else:
                    traverseLogger.error("This URI did NOT return XML or Json contenttype, is this not a Redfish resource (is this redirected?): {}".format(URILink))
                    decoded = None
                    if isXML:
                        traverseLogger.info('Attempting to interpret as XML')
                        decoded = response.text
                    else:
                        try:
                            json.loads(response.text)
                            traverseLogger.info('Attempting to interpret as JSON')
                            decoded = response.json(object_pairs_hook=OrderedDict)
                        except ValueError:
                            pass

                return decoded is not None, decoded, statusCode, elapsed, response
            elif statusCode == 401:
                if inService and AuthType in ['Basic', 'Token']:
                    if AuthType == 'Token':
                        cred_type = 'token'
                    else:
                        cred_type = 'username and password'
                    raise AuthenticationError('Error accessing URI {}. Status code "{} {}". Check {} supplied for "{}" authentication.\nAborting test due to invalid credentials.'
                                              .format(URILink, statusCode, responses[statusCode], cred_type, AuthType))
            elif statusCode >= 400:
                # Error accessing the resource (beyond auth errors)
                return False, None, statusCode, elapsed, response

        except requests.exceptions.SSLError as e:
            traverseLogger.error("SSLError on {}: {}".format(URILink, repr(e)))
            traverseLogger.debug("output: ", exc_info=True)
        except requests.exceptions.ConnectionError as e:
            traverseLogger.error("ConnectionError on {}: {}".format(URILink, repr(e)))
            traverseLogger.debug("output: ", exc_info=True)
        except requests.exceptions.Timeout as e:
            traverseLogger.error("Request has timed out ({}s) on resource {}".format(timeout, URILink))
            traverseLogger.debug("output: ", exc_info=True)
        except requests.exceptions.RequestException as e:
            traverseLogger.error("Request has encounted a problem when getting resource {}: {}".format(URILink, repr(e)))
            traverseLogger.debug("output: ", exc_info=True)
        except AuthenticationError as e:
            raise e  # re-raise exception
        except Exception as e:
            traverseLogger.error("A problem when getting resource {} has occurred: {}".format(URILink, repr(e)))
            traverseLogger.debug("output: ", exc_info=True)
            if response and response.text:
                traverseLogger.debug("payload: {}".format(response.text))

        if payload is not None:
            return True, payload, -1, 0, response
        return False, None, statusCode, elapsed, response


def callResourceURI(URILink):
    if currentService is None:
        traverseLogger.warning("The current service is not setup!  Program must configure the service before contacting URIs")
        raise RuntimeError
    else:
        return currentService.callResourceURI(URILink)


def createResourceObject(name, uri, jsondata=None, typename=None, context=None, parent=None, isComplex=False):
    """
    Factory for resource object, move certain work here
    """    # Create json from service or from given

    if jsondata is None and not isComplex:
        success, jsondata, status, response_time, response = callResourceURI(uri)
        traverseLogger.debug('{}, {}, {}'.format(success, jsondata, status))
        if not success:
            my_logger.error('{}:  URI could not be acquired: {}'.format(uri, status))
            return None, status
    else:
        success, jsondata, status, response_time, response = True, jsondata, -1, 0, None

    # Collect our resource header
    if response:
        my_header = response.headers
    elif parent and parent.headers:
        my_header = parent.headers
    else:
        my_header = None
    
    newResource = ResourceObj(name, uri, jsondata, typename, context, parent, isComplex, headers=my_header)

    newResource.rtime = response_time

    return newResource, status


class ResourceObj:
    def __init__(self, name: str, uri: str, jsondata: dict, typename: str, context: str, parent=None, isComplex=False, forceType=False, headers=None):
        self.initiated = False
        self.parent = parent
        self.uri, self.name = uri, name
        self.rtime = 0
        self.headers = headers
        self.status = -1
        self.isRegistry = False
        self.errorIndex = {
        }

        oem = config.get('oemcheck', True)
        acquiredtype = typename if forceType else jsondata.get('@odata.type', typename)

        # Check if we provide a valid json
        self.jsondata = jsondata

        traverseLogger.debug("payload: {}".format(json.dumps(self.jsondata, indent=4, sort_keys=True)))

        if not isinstance(self.jsondata, dict):
            traverseLogger.error("Resource no longer a dictionary...")
            raise ValueError('This Resource is no longer a Dictionary')

        # Check for @odata.id (todo: regex)
        odata_id = self.jsondata.get('@odata.id')
        if odata_id is None and not isComplex:
            if self.isRegistry:
                traverseLogger.debug('{}: @odata.id missing, but not required for Registry resource'
                                     .format(self.uri))
            else:
                traverseLogger.error('{}: Json does not contain @odata.id'.format(self.uri))

        # Get our real type (check for version)
        if acquiredtype is None:
            traverseLogger.error(
                '{}:  Json does not contain @odata.type or NavType'.format(uri))
            raise ValueError
        if acquiredtype is not typename and isComplex:
            context = None

        if typename is not None:
            if not oem and 'OemObject' in typename:
                acquiredtype = typename

        if currentService:
            if not oem and 'OemObject' in acquiredtype:
                pass

        # Provide a context for this (todo: regex)
        if context is None:
            context = self.jsondata.get('@odata.context')
            if context is None:
                context = createContext(acquiredtype)
                if self.isRegistry:
                    # If this is a Registry resource, @odata.context is not required; do our best to construct one
                    traverseLogger.debug('{}: @odata.context missing from Registry resource; constructed context {}'
                                         .format(acquiredtype, context))
                elif isComplex:
                    pass
                else:
                    traverseLogger.debug('{}:  Json does not contain @odata.context'.format(uri))

        self.context = context

        # Check if we provide a valid type (todo: regex)
        self.typename = acquiredtype
        typename = self.typename

        self.initiated = True

    @staticmethod
    def checkPayloadConformance(jsondata, uri):
        """
        checks for @odata entries and their conformance
        These are not checked in the normal loop
        """
        messages = dict()
        decoded = jsondata
        success = True
        for key in [k for k in decoded if '@odata' in k]:
            paramPass = False

            if key == '@odata.id':
                paramPass = isinstance(decoded[key], str)
                paramPass = re.match(
                    '(\/.*)+(#([a-zA-Z0-9_.-]*\.)+[a-zA-Z0-9_.-]*)?', decoded[key]) is not None
                if not paramPass:
                    traverseLogger.error("{} {}: Expected format is /path/to/uri, but received: {}".format(uri, key, decoded[key]))
                else:
                    if decoded[key] != uri:
                        traverseLogger.warning("{} {}: Expected @odata.id to match URI link {}".format(uri, key, decoded[key]))
            elif key == '@odata.count':
                paramPass = isinstance(decoded[key], int)
                if not paramPass:
                    traverseLogger.error("{} {}: Expected an integer, but received: {}".format(uri, key, decoded[key]))
            elif key == '@odata.context':
                paramPass = isinstance(decoded[key], str)
                paramPass = re.match(
                    '/redfish/v1/\$metadata#([a-zA-Z0-9_.-]*\.)[a-zA-Z0-9_.-]*', decoded[key]) is not None
                if not paramPass:
                    traverseLogger.warning("{} {}: Expected format is /redfish/v1/$metadata#ResourceType, but received: {}".format(uri, key, decoded[key]))
                    messages[key] = (decoded[key], 'odata',
                                    'Exists',
                                    'WARN')
                    continue
            elif key == '@odata.type':
                paramPass = isinstance(decoded[key], str)
                paramPass = re.match(
                    '#([a-zA-Z0-9_.-]*\.)+[a-zA-Z0-9_.-]*', decoded[key]) is not None
                if not paramPass:
                    traverseLogger.error("{} {}: Expected format is #Namespace.Type, but received: {}".format(uri, key, decoded[key]))
            else:
                paramPass = True

            success = success and paramPass

            messages[key] = (decoded[key], 'odata',
                            'Exists',
                            'PASS' if paramPass else 'FAIL')