# Make RDS backup retention period 30 days

This job makes the RDS backup retention period 30 days.
It first tries to modify the retention period of the DB instance.
If that fails, it will try to set the retention period of the DB cluster that the instance belongs to.

## Getting Started

### Prerequisites

The provided AWS credential must have access to `rds:ModifyDBCluster` and `rds:ModifyDBInstance`.

You may find the latest example policy file [here](minimum_policy.json).

### Running the script

You may run this script using following commands:
```shell script
  pip install -r ../../requirements.txt
  python3 rds_backup_retention_30_days.py
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
