# Close Port 8080 for all Security Groups associated with an EC2 Instance

This job blocks public access to port 8080 for both IPv4 and IPv6 for all security groups associated with an EC2 instance by removing all the ingress security group rules containing port 8080 in the port range and source as "0.0.0.0/0" or "::/0".

### Applicable Rule

##### Rule ID:
5c8c26407a550e1fb6560c3c

##### Rule Name:
EC2 instance should restrict public access to TCP port (8080)

## Getting Started

### Prerequisites

The provided AWS credential must have access to `ec2:DescribeInstances`, `ec2:RevokeSecurityGroupIngress`, `ec2:DescribeSecurityGroupRules`.

You may find the latest example policy file [here](minimum_policy.json)

### Running the script

You may run this script using following commands:
```shell script
  pip install -r ../../requirements.txt
  python3 ec2_close_port_8080.py
```

## Running the tests
You may run test using following command under vss-remediation-worker-job-code-python directory:
```shell script
    python3 -m pytest
```

## Contributing
The VMware Aria Automation for Secure Clouds team welcomes welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).
All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to [CONTRIBUTING.md](../../../CONTRIBUTING.md).

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/vmware-samples/secure-state-remediation-jobs/tags).

## Authors

* **VMware VMware Aria Automation for Secure Clouds** - *Initial work*

See also the list of [contributors](https://github.com/vmware-samples/secure-state-remediation-jobs/contributors) who participated in this project.

## License

This project is licensed under the Apache License - see the [LICENSE](https://github.com/vmware-samples/secure-state-remediation-jobs/blob/master/LICENSE.txt) file for details
