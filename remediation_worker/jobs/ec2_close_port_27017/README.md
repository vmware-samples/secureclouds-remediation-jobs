# Close Port 27017 for all Security Groups associated with an EC2 Instance

This job blocks public access to port 27017 for both IPv4 and IPv6 for all security groups associated with an EC2 instance.

### Applicable Rule

##### Rule ID:
5c8c26427a550e1fb6560c40

##### Rule Name:
EC2 instance should restrict public access to MongoDB server port (27017)


## Getting Started

### Prerequisites

The provided AWS credential must have access to `ec2:DescribeInstances` and `ec2:RevokeSecurityGroupIngress`.

You may find the latest example policy file [here](minimum_policy.json)

### Running the script

You may run this script using following commands:
```shell script
  pip install -r ../../requirements.txt
  python3 ec2_close_port_27017.py
```

## Running the tests
You may run test using following command under vss-remediation-worker-job-code-python directory:
```shell script
    python3 -m pytest
```

## Contributing
The Secure State team welcomes welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).
All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to [CONTRIBUTING.md](../../../CONTRIBUTING.md).

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/vmware-samples/secure-state-remediation-jobs/tags).

## Authors

* **VMware Secure State** - *Initial work*

See also the list of [contributors](https://github.com/vmware-samples/secure-state-remediation-jobs/contributors) who participated in this project.

## License

This project is licensed under the Apache License - see the [LICENSE](https://github.com/vmware-samples/secure-state-remediation-jobs/blob/master/LICENSE.txt) file for details
