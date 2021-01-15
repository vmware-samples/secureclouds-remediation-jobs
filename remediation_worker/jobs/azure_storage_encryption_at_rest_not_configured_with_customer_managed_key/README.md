# Configure Storage Account Encryption at rest with Customer Managed Keys

This job configures Storage Account Encryption at rest with Customer Managed Keys.

### Applicable Rule

##### Rule ID:
02b672b7-a590-4434-8188-19325b2d1864

##### Rule Name:
Storage account encryption at rest is not configured with customer-managed key (CMK)

## Getting Started
### Prerequisites
The provided Azure service principal must have the following permissions:
`Microsoft.Storage/storageAccounts/read`
`Microsoft.Storage/storageAccounts/write`
`Microsoft.KeyVault/vaults/read`
`Microsoft.KeyVault/vaults/write`
`Microsoft.KeyVault/vaults/keys/read`
`Microsoft.KeyVault/vaults/keys/write`

A sample role with requisite permissions can be found [here](minimum_permissions.json)

More information about already builtin roles and permissions can be found [here](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)

### Running the script
You may run this script using following commands:

```shell script
  pip install -r requirements.txt
  python3 azure_storage_encryption_at_rest_not_configured_with_customer_managed_key.py
```
## Running the tests
You may run test using following command under vss-remediation-worker-job-code-python directory:

```shell script
    pip install -r requirements-dev.txt
    python3 -m pytest test
```
## Deployment
Provision a Virtual Machine Create an EC2 instance to use for the worker. The minimum required specifications are 128 MB memory and 1/2 Core CPU.
Setup Docker Install Docker on the newly provisioned EC2 instance. You can refer to the [docs here](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/docker-basics.html) for more information.
Deploy the worker image SSH into the EC2 instance and run the command below to deploy the worker image:
  ```shell script
  docker run --rm -it --name worker \
  -e VSS_CLIENT_ID={ENTER CLIENT ID}
  -e VSS_CLIENT_SECRET={ENTER CLIENT SECRET} \
  vmware/vss-remediation-worker:latest-python
  ```
## Contributing
The Secure State team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).

All contributions to this repository must be signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on as an open-source patch.

For more detailed information, refer to [CONTRIBUTING.md](../../../CONTRIBUTING.md).
## Versioning
We use SemVer for versioning. For the versions available, see the tags on this repository.

## Authors
* **VMware Secure State** - *Initial work*
See also the list of [contributors](https://github.com/vmware-samples/secure-state-remediation-jobs/graphs/contributors) who participated in this project.

## License
This project is licensed under the Apache License - see the [LICENSE](https://github.com/vmware-samples/secure-state-remediation-jobs/blob/master/LICENSE.txt) file for details
