# List S3 Buckets

This job lists all s3 bucket in your account.

## Getting Started

### Prerequisites

The provided AWS credential must have access to `s3:ListBucket`.

You may find the latest example policy file [here](minimum_policy.json)

### Running the script

You may run this script using following commands:
```shell script
  pip install -r ../../requirements.txt
  python3 s3_list_buckets.py
```

## Running the tests
You may run test using following command under vss-remediation-worker-job-code-python directory:
```shell script
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
  -e WORKER_GROUP_ID={ENTER GROUP ID} \
  -e VSS_CLIENT_ID={ENTER CLIENT ID}
  -e VSS_CLIENT_SECRET={ENTER CLIENT SECRET} \
  -e VSS_ORG_ID={ENTER ORG ID} \
  -e VSS_STARTUP_HOST=https://api.securestate.vmware.com \
  registry.securestate.vmware.com/vss-remediation-worker-pythonmaster:latest
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
