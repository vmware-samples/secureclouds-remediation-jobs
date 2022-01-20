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


class RDSSnapShotRemovePublicAccess():
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

        snapshot_identifier = finding_info.get("ObjectId", None)
        region = finding_info.get("Region", None)

        if snapshot_identifier is None:
            logging.error("Missing parameters for 'RDS SNAPSHOT IDENTIFIER'.")
            raise Exception("Missing parameters for 'RDS SNAPSHOT IDENTIFIER'.")

        if region is None:
            logging.error("Missing parameters for 'REGION'.")
            raise Exception("Missing parameters for 'REGION'.")

        logging.info("parsed params")
        logging.info("  rds snapshot identifier: %s", snapshot_identifier)
        logging.info("  region: %s", region)

        return {
            "instance_id": snapshot_identifier,
            "region": region
        }

    def remediate(self, client, snapshot_identifier):
        """
        Removes public access from RDS snapshots
        and makes the snapshots share private.

        Args:
            snapshot_identifier ([str]): The identifier of the RDS snapshot.
            client: Instance of the AWS boto3 client.
        """

        logging.info("Beginning RDS snapshot share public evaluation.")

        # Check to see if the database snapshot
        # is shared publicly 
        logging.info("executing client.describe_db_snapshot_attributes")
        logging.info(f"RDS instance={snapshot_identifier}")
        snapshot_attrs_result = client.describe_db_snapshot_attributes(DBSnapshotIdentifier=snapshot_identifier).get('DBSnapshotAttributesResult')
        snapshot_attrs = snapshot_attrs_result.get("DBSnapshotAttributes")
        snapshot_restore_attr = next(snapshot_attr for snapshot_attr in snapshot_attrs if snapshot_attr["AttributeName"] == "restore")
        is_public = True if "all" in snapshot_restore_attr["AttributeValues"] else False
        # If it is public, set to private
        if is_public:
            logging.info(
                "RDS snapshot %s is public, removing public access...",
                snapshot_identifier
                )
            try:
                logging.info("executing client.modify_db_snapshot_attribute and apply immediately")
                logging.info("Attribute=Restore,Remove all AttributeValue")
                client.modify_db_snapshot_attribute(
                    DBSnapshotIdentifier=snapshot_identifier,
                    AttributeName="restore",ValuesToRemove=["all"]
                    )
                logging.info(
                    "RDS snapshot %s is now private.",
                    snapshot_identifier
                )
            except ClientError as state_err:
                # If the remediation is run during maintenance
                # or a creation/modification, inform it is not in the right state
                # user should retry.
                # This is b/c you can describe a bad instance state
                # with no errors, but not modify.
                # Otherwise, we would catch this error
                # on the "describe_db_snapshot_attributes" call
                if state_err.response["Error"]["Code"] == "InvalidDBSnapshotState":
                    logging.info(
                        "RDS database snapshot %s is in an unavailable state. Waiting..",
                        snapshot_identifier
                    )
                    
                logging.error(
                        "Remediation RDS database snapshot %s failed",
                        snapshot_identifier
                )
                return 1
            except Exception as e:
               error = "Receiving other exceptions {0} while setting RDS database snapshot {1} to private".format(str(e), snapshot_identifier)
               logging.error(error) 
               return 1

        else:
            logging.info(
                "RDS database snapshot %s is private, taking no action.",
                snapshot_identifier
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
        "aws_rds_snapshot_remove_public_access.py called - running now %s",
        sys.argv[0]
        )
    obj = RDSSnapShotRemovePublicAccess()
    obj.run(sys.argv)
