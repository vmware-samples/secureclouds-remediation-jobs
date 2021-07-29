# Copyright (c) 2021 VMware Inc.
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

from __future__ import annotations

import json
import logging
import sys

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)


class RDSRemovePublicEndpoint():
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        Args:
            payload: (str) JSON string containing parameters
                    received from the remediation service.

        Raises:
            Exception: JSONDecodeError

        Returns:
            (dict) Dictionary of parsed parameters.
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)

        instance_id = finding_info.get("ObjectId", None)
        region = finding_info.get("Region", None)

        if instance_id is None:
            logging.error("Missing parameters for 'INSTANCE_ID'.")
            raise Exception("Missing parameters for 'INSTANCE_ID'.")

        if region is None:
            logging.error("Missing parameters for 'REGION'.")
            raise Exception("Missing parameters for 'REGION'.")

        logging.info("parsed params")
        logging.info("  instance_id: %s", instance_id)
        logging.info("  region: %s", region)

        return {
            "instance_id": instance_id,
            "region": region
        }

    def remediate(self, client, instance_id):
        """
        Removes public access from RDS instances
        and makes the instances private.

        Args:
            instance_id ([str]): The ID of the RDS instance.
            client: Instance of the AWS boto3 client.
        """

        logging.info("Beginning RDS public endpoint evaluation.")

        # Check to see if the database
        # is publicly accessible
        logging.info("executing client.describe_db_instances")
        logging.info(f"RDS instance={instance_id}")
        is_public = client.describe_db_instances(
            DBInstanceIdentifier=instance_id).get(
                "DBInstances")[0]["PubliclyAccessible"]

        # If it is public, set to private
        if is_public:
            logging.info(
                "RDS database %s is public, setting to private...",
                instance_id
                )
            try:
                logging.info("executing client.modify_db_instance and apply immediately")
                logging.info("Attribute=PubliclyAccessible")
                client.modify_db_instance(
                    DBInstanceIdentifier=instance_id,
                    PubliclyAccessible=False,
                    ApplyImmediately=True
                    )
                logging.info(
                    "RDS database %s is now private.",
                    instance_id
                )
            except ClientError as state_err:
                # If the remediation is run during maintenance
                # or a creation/modification, inform it is not in the right state
                # user should retry.
                # This is b/c you can describe a bad instance state
                # with no errors, but not modify.
                # Otherwise, we would catch this error
                # on the "describe_db_instances" call
                if state_err.response["Error"]["Code"] == "InvalidDBInstanceState":
                    logging.info(
                        "RDS database %s is in an unavailable state. Waiting..",
                        instance_id
                    )
                    
                logging.error(
                        "Remediation RDS database %s failed",
                        instance_id
                )
                return 1
            except Exception as e:
               error = "Receiving other exceptions {0} while setting RDS database {1} to private".format(str(e), instance_id)
               logging.error(error) 
               return 1

        else:
            logging.info(
                "RDS database %s is private, taking no action.",
                instance_id
            )
        return 0

    def run(self, args):
        """
        Run the remediation job.

        Args:
            args ([list]): List of arguments provided to the job.

        Returns:
            [int]
        """
        params = self.parse(args[1])
        client = boto3.client("rds", region_name=params['region'])

        logging.info(
            "acquired rds client and parsed params - starting remediation"
            )

        return self.remediate(client, params['instance_id'])


if __name__ == "__main__":
    logging.info(
        "rds_remove_public_endpoint.py called - running now %s",
        sys.argv[0]
        )
    obj = RDSRemovePublicEndpoint()
    obj.run(sys.argv)
