# Close Port 22 for a VM

This job blocks public access to port 22 for the VM

## Getting Started

### Prerequisites

The provided Azure service principal must have permissions to make changes to the network security groups and security
rules.
Details for the permissions can be found [here](https://docs.microsoft.com/en-us/azure/virtual-network/manage-network-security-group#permissions):


### Running the script

You may run this script using following commands:
```shell script
  pip install -r ../../requirements.txt
  python3 azure_vm_close_port_22.py
```

## Running the tests
You may run test using following command under vss-remediation-worker-job-code-python directory:
```shell script
    python3 -m pytest test
```

## Contributing
The Secure State team welcomes welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).
All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to [CONTRIBUTING.md](../../../CONTRIBUTING.md).

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags).

## Authors

* **VMware Secure State** - *Initial work*

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the Apache License - see the [LICENSE](https://github.com/vmware-samples/secure-state-remediation-jobs/blob/master/LICENSE.txt) file for details