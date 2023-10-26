# Copyright Notice:
# Copyright 2016-2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/Redfish-Interop-Validator/blob/master/LICENSE.md

from redfish_interop_validator.RedfishInteropValidator import main, my_logger
import sys

if __name__ == '__main__':
    try:
        status_code, lastResultsPage, exit_string = main()
        sys.exit(status_code)
    except Exception as e:
        my_logger.exception("Program finished prematurely: %s", e)
        raise
