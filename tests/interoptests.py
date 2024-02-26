
# Copyright Notice:
# Copyright 2017 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Usecase-Checkers/LICENSE.md
#
# Unit tests for RedfishInteropValidator.py
#

from unittest import TestCase

import redfish_interop_validator.interop as riv

import logging

logging.Logger.verbose1 = logging.Logger.debug
logging.Logger.verbose2 = logging.Logger.debug


class ValidatorTest(TestCase):

    # can we test writeable, find_prop, conditional
    # propReadRequirements?

    def test_no_test(self):
        self.assertTrue(True, 'Huh?')

    def test_requirement(self):
        entries = ['Mandatory', 'Recommended', 'Mandatory', 'Recommended']
        vals = ['Ok', riv.REDFISH_ABSENT, riv.REDFISH_ABSENT, 'Ok']
        boolist = [True, True, False, True]
        for e, v, b in zip(entries, vals, boolist):
            self.assertTrue(riv.validateRequirement(e, v)[1] == b, str(e + ' ' + v))

    def test_mincount(self):
        x = 'x'
        entries = [1, 2, 3, 4]
        vals = [[x, x, x], [x], [x, x, x, x], [x, x, x, x]]
        annotations = [3, 1, 4, 4]
        boolist = [True, False, True, True]
        for e, v, a, b in zip(entries, vals, annotations, boolist):
            self.assertTrue(riv.validateMinCount(v, e, a)[1] == b)

    def test_supportedvals(self):
        x, y, z = 'x', 'y', 'z'
        entries = [[x, y], [x], [x, y, z]]
        vals = [[x, y], [x, y], [x, y]]
        boolist = [True, True, False]
        for e, v, b in zip(entries, vals, boolist):
            self.assertTrue(riv.validateSupportedValues(e, v)[1] == b)

    def test_comparison_1(self):
        x, y, z = 'x', 'y', 'z'
        comp = ['AnyOf', 'AllOf', 'AllOf']
        entries = [[x, y], [x], [x, y, z]]
        vals = [[x, y], [x, y], [x, y, y]]
        boolist = [True, True, False]
        for c, e, v, b in zip(comp, entries, vals, boolist):
            self.assertTrue(riv.checkComparison(v, c, e)[1] == b)

    def test_members(self):
        members = [1, 2, 3]
        entry = {'MinCount': 2}
        annotation = 3
        self.assertTrue(riv.validateMembers(members, entry, annotation)[1])

    def test_minversion(self):
        entries = ['1.0.1', '1.0.1', '1.2.0', '1.0.0', '1.0', '1.1']
        vals = ['#ComputerSystem.1.0.1.ComputerSystem', '#ComputerSystem.v1_1_1.ComputerSystem',
                '#ComputerSystem.v1_1_1.ComputerSystem', '1.0.0', '1.0.0', '1.0.0']
        boolist = [True, True, False, True, True, False]
        for e, v, b in zip(entries, vals, boolist):
            self.assertTrue(riv.validateMinVersion(v, e)[1] == b, "Failed on {} {} {}".format(e, v, b))

    def test_action(self):
        interopdict = {
                    "ResetType@Redfish.AllowableValues": ["On", "ForceOff"],
                    "target": "/redfish/v1/Chassis/System.Embedded.1/Actions/Chassis.Reset"}
        vals = [interopdict,
                riv.REDFISH_ABSENT, riv.REDFISH_ABSENT, interopdict, {}]
        entries = [{
                    "ReadRequirement": "Mandatory",
                    "Parameters": {
                        "ResetType": {
                            "AllowableValues": ["On", "ForceOff"],
                            "ReadRequirement": "Mandatory"
                        }
                    }
                }, {
                    "ReadRequirement": "Mandatory",
                }, {
                    "ReadRequirement": "Recommended",
                }, {
                    "ReadRequirement": "Recommended",
                    "Parameters": {
                        "ResetType": {
                            "AllowableValues": ["ForceOff", "PowerCycle"],
                            "ReadRequirement": "Mandatory"
                        }
                    }
                }, {
                    "ReadRequirement": "Recommended",
                    "Parameters": {
                        "ResetType": {
                            "AllowableValues": ["ForceOff", "PowerCycle"],
                            "ReadRequirement": "Mandatory"
                        }
                    }
                }]
        boolist = [riv.testResultEnum.PASS, riv.testResultEnum.FAIL, riv.testResultEnum.PASS, riv.testResultEnum.PASS, riv.testResultEnum.PASS]
        for e, v, b in zip(entries, vals, boolist):
            self.assertTrue(riv.validateActionRequirement(e, (v, None), '#Chassis.Reset')[0][0].success == b,"Failed on {}".format((e, v, b)))
