# Copyright (c) 2020 VMware Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from botocore.exceptions import ClientError
import json
import logging
import sys

import boto3

logging.basicConfig(level=logging.INFO)


def logcall(f, *args, **kwargs):
    logging.info(
        "%s(%s)",
        f.__name__,
        ", ".join(list(args) + [f"{k}={repr(v)}" for k, v in kwargs.items()]),
    )
    res = f(*args, **kwargs)
    logging.info(res)
    return res


class RDSBackupRetention30Days(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: KeyError, JSONDecodeError
        """
        payload_dict = json.loads(payload)
        return {
            "db_instance_id": payload_dict["notificationInfo"]["FindingInfo"][
                "ObjectId"
            ],
            "region": payload_dict["notificationInfo"]["FindingInfo"]["Region"],
        }

    def remediate(self, client, db_instance_id):
        """Set the backup retention period of a DB instance to 30 days. If the instance belongs to a cluster,
        instead modifies the backup retention period of the cluster.

        :param client: Instance of the AWS boto3 client.
        :param db_instance_id: The ID of the DB instance.
        :type db_instance_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        instance_info = logcall(
            client.describe_db_instances, DBInstanceIdentifier=db_instance_id
        )["DBInstances"][0]

        backup_period = instance_info["BackupRetentionPeriod"]
        db_cluster_id = instance_info.get(
            "DBClusterIdentifier"
        )  # not all instances have a cluster

        if backup_period < 30:
            logging.info("backup retention period %d, changing to 30", backup_period)
            try:
                logcall(
                    client.modify_db_instance,
                    DBInstanceIdentifier=db_instance_id,
                    BackupRetentionPeriod=30,
                    ApplyImmediately=True,
                )
            except ClientError as error:
                if error.response["Error"]["Code"] == "InvalidParameterCombination":
                    logging.info(
                        "modifying instance failed, modifying backup retention period of cluster instead"
                    )
                    logcall(
                        client.modify_db_cluster,
                        DBClusterIdentifier=db_cluster_id,
                        BackupRetentionPeriod=30,
                        ApplyImmediately=True,
                    )
                else:
                    raise error
        else:
            logging.info(
                "backup retention period already %d, not modifying", backup_period
            )

        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        client = boto3.client("rds", region_name=params["region"])
        return self.remediate(client, params["db_instance_id"])


if __name__ == "__main__":
    sys.exit(RDSBackupRetention30Days().run(sys.argv))
