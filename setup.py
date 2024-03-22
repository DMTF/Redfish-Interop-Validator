# Copyright Notice:
# Copyright 2022-2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/Redfish-Interop-Validator/blob/main/LICENSE.md

from setuptools import setup
from codecs import open

with open("README.md", "r", "utf-8") as f:
    long_description = f.read()

setup(
    name="redfish_interop_validator",
    version="2.2.0",
    description="Redfish Interop Validator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DMTF, https://www.dmtf.org/standards/feedback",
    license="BSD 3-clause \"New\" or \"Revised License\"",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Topic :: Communications"
    ],
    keywords="Redfish",
    url="https://github.com/DMTF/Redfish-Interop-Validator",
    packages=["redfish_interop_validator"],
    entry_points={
        'console_scripts': [
            'rf_interop_validator=redfish_interop_validator.RedfishInteropValidator:main'
        ]
    },
    install_requires=[
      "requests",
      "beautifulsoup4>=4.6.0",
      "lxml",
      "jsonschema"
    ]
)
