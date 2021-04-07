# Set Advanced Threat Protection Types to all for SQL Server

This job sets Advanced Threat Protection Types to all for an SQL Server.

### Applicable Rule

##### Rule ID:
5c8c26977a550e1fb6560cd6

##### Rule Name:
SQL server should have Advanced Threat Protection types set to all

## Getting Started
### Prerequisites
The provided Azure service principal must have the following permissions:
`Microsoft.Sql/servers/securityAlertPolicies/write`
`Microsoft.Sql/servers/securityAlertPolicies/read`

A sample role with requisite permissions can be found [here](minimum_permissions.json)

More information about already builtin roles and permissions can be found [here](https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles)

### Running the script
You may run this script using following commands:

```shell script
  pip install -r requirements.txt
  python3 azure_sql_threat_detection_types_all_server.py
```
## Running the tests
You may run test using following command under vss-remediation-worker-job-code-python directory:

```shell script
    pip install -r requirements-dev.txt
    python3 -m pytest test
```
## Deployment
Provision an instance by creating an Azure Virtual Machine to use for the worker. The minimum required specifications are 128 MB memory and 1/2 Core CPU.
Setup Docker on newly provisioned Azure Virtual Machine instance. You can refer to the [docs here](https://docs.microsoft.com/en-us/previous-versions/azure/virtual-machines/linux/docker-machine) for more information.
Deploy the worker docker image by SSH into the Azure Virtual Machine instance and run the following commands:
  ```shell script
  docker run --rm -it --name {worker_name}\
  -e VSS_CLIENT_ID={ENTER CLIENT ID}\
  -e VSS_CLIENT_SECRET={ENTER CLIENT SECRET}\
  -e AZURE_CLIENT_ID={ENTER AZURE_CLIENT_ID} \
  -e AZURE_CLIENT_SECRET={ENTER AZURE_CLIENT_SECRET} \
  -e AZURE_TENANT_ID={ENTER AZURE_TENANT_ID} \
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
