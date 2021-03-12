# Secure State Remediation Jobs
[![License][license-img]][license]

## Table of Contents
- [Abstract](#abstract)
- [Quick Start Guide](#quick-start-guide)
- [Job Execution](#job-execution)
- [Logging](#logging)
- [Supported Remediation Jobs](#supported-remediation-jobs)
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

## Supported Remediation Jobs
The table below lists all the supported jobs with their links.

|                Rule Id               	|                                        Rule Name                                        	|                                                                              Remediation Job Link                                                                              	|
|:------------------------------------:	|:---------------------------------------------------------------------------------------:	|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:	|
|       5c8c26997a550e1fb6560cd9       	|                      Blob container has public read access enabled                      	|                                           [azure_blob_remove_public_access](remediation_worker/jobs/azure_blob_remove_public_access)                                           	|
|       5c8c26687a550e1fb6560c72       	|                               Logging For Keyvault Enabled                              	|                              [azure_key_vault_logging_for_keyvault_enabled](remediation_worker/jobs/azure_key_vault_logging_for_keyvault_enabled)                              	|
|       5c8c26847a550e1fb6560cab       	|         Network security group should restrict SSH port (22) from public access         	|                                [azure_network_security_group_close_port_22](remediation_worker/jobs/azure_network_security_group_close_port_22)                                	|
|       5c8c267e7a550e1fb6560c9c       	|   Network security group should restrict Remote Desktop port (3389) from public access  	|                              [azure_network_security_group_close_port_3389](remediation_worker/jobs/azure_network_security_group_close_port_3389)                              	|
| 3abf3147-ea53-4302-b237-caab4d764c77 	|                        DDoS Protection Standard should be enabled                       	|                              [azure_security_center_enable_ddos_protection](remediation_worker/jobs/azure_security_center_enable_ddos_protection)                              	|
|       5c8c268a7a550e1fb6560cb9       	|                          SQL Server Auditing should be enabled                          	|                                              [azure_sql_auditing_on_server](remediation_worker/jobs/azure_sql_auditing_on_server)                                              	|
|       5c8c268d7a550e1fb6560cc0       	|                          SQL data encryption should be enabled                          	|                                              [azure_sql_data_encryption_on](remediation_worker/jobs/azure_sql_data_encryption_on)                                              	|
|       5c8c26947a550e1fb6560cce       	|                  SQL server should have Azure Defender for SQL enabled                  	|                                      [azure_sql_threat_detection_on_server](remediation_worker/jobs/azure_sql_threat_detection_on_server)                                      	|
|       5c8c269a7a550e1fb6560cdb       	|              Storage account is not configured to allow HTTPS-only traffic              	|                            [azure_storage_account_allow_https_traffic_only](remediation_worker/jobs/azure_storage_account_allow_https_traffic_only)                            	|
| 99d645b8-aa87-11ea-bb37-0242ac130002 	|                          Storage account is publicly accessible                         	|                                 [azure_storage_default_network_access_deny](remediation_worker/jobs/azure_storage_default_network_access_deny)                                 	|
| 02b672b7-a590-4434-8188-19325b2d1864 	|   Storage account encryption at rest is not configured with customer-managed key (CMK)  	| [azure_storage_encryption_at_rest_not_configured_with_customer_managed_key](remediation_worker/jobs/azure_storage_encryption_at_rest_not_configured_with_customer_managed_key) 	|
| 643eb5fc-7747-4df4-b217-41c4e97e0c07 	|             Storage account blob service is not configured with soft delete             	|                                     [azure_storage_soft_delete_not_enabled](remediation_worker/jobs/azure_storage_soft_delete_not_enabled)                                     	|
| d7a3ad03-860c-4928-9ba8-789e84a835be 	| Virtual machine scale set VMs are publicly accessible to the internet via SSH port (22) 	|                                                    [azure_vm_close_port_22](remediation_worker/jobs/azure_vm_close_port_22)                                                    	|
|       5c8c26417a550e1fb6560c3f       	|               EC2 instance should restrict public access to SSH port (22)               	|                                                         [ec2_close_port_22](remediation_worker/jobs/ec2_close_port_22)                                                         	|
|       5c8c26437a550e1fb6560c42       	|      EC2 security group should restrict public access to Remote Desktop port (3389)     	|                                                       [ec2_close_port_3389](remediation_worker/jobs/ec2_close_port_3389)                                                       	|
| 657c46b7-1cd0-4cce-80bb-9d195f49c987 	|                    Elastic Load Balancer access logs are not enabled                    	|                                                    [elb_enable_access_logs](remediation_worker/jobs/elb_enable_access_logs)                                                    	|
|       5c8c264a7a550e1fb6560c4d       	|                   The RDS backup retention period is less than 30 days                  	|                                              [rds_backup_retention_30_days](remediation_worker/jobs/rds_backup_retention_30_days)                                              	|
|       5c8c265e7a550e1fb6560c67       	|                           S3 access logging should be enabled                           	|                                                  [s3_enable_access_logging](remediation_worker/jobs/s3_enable_access_logging)                                                  	|
| 1d187035-9fff-48b2-a7c3-ffc56a4da5e6 	|                      S3 bucket default encryption should be enabled                     	|                                              [s3_enable_default_encryption](remediation_worker/jobs/s3_enable_default_encryption)                                              	|
|       5c8c26507a550e1fb6560c57       	|                       S3 bucket should restrict full public access                      	|                                                   [s3_remove_public_access](remediation_worker/jobs/s3_remove_public_access)                                                   	|
|       5c8c26517a550e1fb6560c59       	|                       S3 bucket should restrict public read access                      	|                                                   [s3_remove_public_access](remediation_worker/jobs/s3_remove_public_access)                                                   	|
|       5c8c26537a550e1fb6560c5a       	|                     S3 bucket should restrict public read ACL access                    	|                                                   [s3_remove_public_access](remediation_worker/jobs/s3_remove_public_access)                                                   	|
|       5c8c26537a550e1fb6560c5b       	|                      S3 bucket should restrict public write access                      	|                                                   [s3_remove_public_access](remediation_worker/jobs/s3_remove_public_access)                                                   	|
|       5c8c26547a550e1fb6560c5c       	|                    S3 bucket should restrict public write ACL access                    	|                                                   [s3_remove_public_access](remediation_worker/jobs/s3_remove_public_access)                                                   	|
|       5c8c26637a550e1fb6560c6b       	|                    S3 bucket policy should restrict public get access                   	|                                                   [s3_remove_public_access](remediation_worker/jobs/s3_remove_public_access)                                                   	|
|       5c8c26617a550e1fb6560c69       	|                   S3 bucket policy should restrict full public access                   	|                                                   [s3_remove_public_access](remediation_worker/jobs/s3_remove_public_access)                                                   	|
|       5c8c25ec7a550e1fb6560bbe       	|            EC2 security group should restrict public access to SSH port (22)            	|                                              [security_group_close_port_22](remediation_worker/jobs/security_group_close_port_22)                                              	|
|       5c8c25ef7a550e1fb6560bc4       	|         EC2 instance should restrict public access to Remote Desktop port (3389)        	|                                            [security_group_close_port_3389](remediation_worker/jobs/security_group_close_port_3389)                                            	|
|       5c8c25f07a550e1fb6560bc6       	|       EC2 instance should restrict public access to PostgreSQL server port (5432)       	|                                            [security_group_close_port_5432](remediation_worker/jobs/security_group_close_port_5432)                                            	|
|       5c8c25e47a550e1fb6560bac       	|                           CloudTrail logs should be encrypted                           	|                                             [aws_cloudtrail_logs_encrypted](remediation_worker/jobs/aws_cloudtrail_logs_encrypted)                                             	|
|       5c8c26217a550e1fb6560c12       	|                        KMS automated key rotation is not enabled                        	|                                                       [aws_kms_key_rotates](remediation_worker/jobs/aws_kms_key_rotates)                                                       	|
|       5c8c265c7a550e1fb6560c63       	|                 CloudTrail S3 buckets should have access logging enabled                	|                                                  [s3_enable_access_logging](remediation_worker/jobs/s3_enable_access_logging)                                                  	|
|       5c8c265d7a550e1fb6560c65       	|              CloudTrail S3 buckets should restrict access to required users             	|                                           [aws_s3_cloudtrail_public_access](remediation_worker/jobs/aws_s3_cloudtrail_public_access)                                           	|

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
