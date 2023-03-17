# Enable Elastic Load Balancer access logs

This job enables access logs for a classic Elastic Load Balancer (if they are not already enabled).
It will create a new S3 bucket with the required permissions and configure it to receive access logs from the ELB.

### Applicable Rule

##### Rule ID:
657c46b7-1cd0-4cce-80bb-9d195f49c987

##### Rule Name:
Elastic Load Balancer access logs are not enabled

## Getting Started

### Prerequisites

The provided AWS credential must have access to `elb:DescribeLoadBalancerAttributes`, `s3:CreateBucket`, `s3:PutBucketPolicy`, and `elb:ModifyLoadBalancerAttributes`.

You may find the latest example policy file [here](minimum_policy.json).

### Running the script

You may run this script using following commands:
```shell script
  pip install -r ../../requirements.txt
  python3 elb_enable_access_logs.py
```

## Running the tests
You may run test using following command under vss-remediation-worker-job-code-python directory:
```shell script
    pip install -r requirements-dev.txt
    python3 -m pytest test
```
## Deployment
1. Provision a Virtual Machine
Create an EC2 instance to use for the worker. The minimum required specifications are 128 MB memory and 1/2 Core CPU.
2. Setup Docker
Install Docker on the newly provisioned EC2 instance. You can refer to the [docs here](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/docker-basics.html) for more information.
3. Deploy the worker image
SSH into the EC2 instance and run the command below to deploy the worker image:
```shell script
  docker run --rm -it --name worker \
  -e VSS_CLIENT_ID={ENTER CLIENT ID}
  -e VSS_CLIENT_SECRET={ENTER CLIENT SECRET} \
  vmware/vss-remediation-worker:latest-python
```


## Contributing
The VMware Aria Automation for Secure Clouds team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).
All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to [CONTRIBUTING.md](../../../CONTRIBUTING.md).

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/vmware-samples/secure-state-remediation-jobs/tags).

## Authors

* **VMware VMware Aria Automation for Secure Clouds** - *Initial work*

See also the list of [contributors](https://github.com/vmware-samples/secure-state-remediation-jobs/contributors) who
 participated in this project.

## License

This project is licensed under the Apache License - see the [LICENSE](https://github.com/vmware-samples/secure-state-remediation-jobs/blob/master/LICENSE.txt) file for details