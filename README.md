# Secure State Remediation Jobs
[![License][license-img]][license]

## Table of Contents
- [Abstract](#abstract)
- [Quick Start Guide](#quick-start-guide)
- [Job Execution](#job-execution)
- [Logging](#logging)
- [Contributing](#contributing)
- [Repository Administrator Resources](#repository-administrator-resources)
- [VMware Resources](#vmware-resources)

## Abstract
These jobs represent open-sourced remediation jobs to be used in conjunction with the
[SecureState remediation worker for python](https://hub.docker.com/r/vmware/vss-remediation-worker). In order
to make use of this code, you must utilize the worker and have a SecureState workergroup properly set up.

## Quick Start Guide
There are a couple conventions that must be followed in order to contribute working jobs to this repository:
* The directory structure and
* The file names

Each job must be entire self-contained within a directory, which is where the job gets its name from.
For example, a directory by the name of `s3-remove-public-access` will result in a job
called `s3-remove-public-access`

In order to execute a python job, the file must be named the same as the directory with a `.py` extension.
For example, the job `s3-remove-public-access` must have a `s3-remove-publc-access.py` file within that directory.

The `requirements.txt` file and the `constraints.txt` file are optional but recommended. This ensures
the worker can install the requirements in a repeatable fashion, which ensures the SecureState
application will not invalidate jobs due to new requirements being installed.

## Job execution
When the worker runs, all requirements found in the (optional) `requirements.txt` and `constraints.txt` files will be installed relative to the job
directory. When the job is executed, the python runtime is restricted to the requirements in that relative path.
This ensures all code being executed is known to the SecureState worker and can be verified
via checksum. The worker also moves the entire folder to a separate working directory to
ensure local imports will not work.

The worker executes jobs in a fashion similar to running `python ./s3-remove-publc-access/s3-remove-publc-access.py {... finding payload json ...}`

The finding payload is in the form:
```$json
{
  "notificationInfo": {
    "CloudAccountID" : <string>,
    "RuleID": <string>,
    "RuleName": <string>,
    "RuleDisplayName": <string>,
    "Level": <string>,
    "Service": <string>,
    "FindingInfo": {
      "FindingId": <string>,
      "ObjectId": <string>,
      "ObjectChain": <string>,
      "CloudTags": {
        "<key1>": "<value1>",
        "<key2>": "<value2>",
      },
      "RiskScore": <integer>,
      "Region": <string>,
      "Service": <string>
    }
  },
  "autoRemediate": <boolean>
}
```

## Logging
All stdout and stderr logs are sent to the SecureState web application for display in the
user interface. Take care when logging and make sure not to log sensitive data.

## Contributing
The Secure State team welcomes welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).
All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## Repository Administrator Resources
### Board Members
Board members are volunteers from the community and VMware staff members, board members are not held responsible for any issues which may occur from running of samples from this repository.

Members:
* Paul Allen (VMware)

## VMware Resources
* [VMware SecureState](https://www.cloudhealthtech.com/products/vmware-secure-state)
* [VMware Code](https://code.vmware.com/home)
* [VMware Developer Community](https://communities.vmware.com/community/vmtn/developer)

## Feedback
If you find a bug, please open a [GitHub issue](https://github.com/vmware-samples/secure-state-remediation-jobs/issues).

[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://opensource.org/licenses/Apache-2.0
