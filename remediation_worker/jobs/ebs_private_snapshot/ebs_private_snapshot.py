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

import json
import logging
import sys

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)


class EBSPrivateSnapshot:
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        :param payload: JSON string containing parameters sent to the remediation job.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        logging.debug(payload)
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)

        snapshot_id = finding_info.get("ObjectId", None)
        region = finding_info.get("Region", None)

        if snapshot_id is None:
            logging.error("Missing parameters for 'SNAPSHOT_ID'.")
            raise Exception("Missing parameters for 'SNAPSHOT_ID'.")

        if region is None:
            logging.error("Missing parameters for 'REGION'.")
            raise Exception("Missing parameters for 'REGION'.")

        logging.debug("parsed params")
        logging.debug(f"  snapshot_id: {snapshot_id}")
        logging.info(f"  region: {region}")

        return {
            "snapshot_id": snapshot_id,
            "region": region
        }

    def remediate(self, client, snapshot_id, region):
        
        """Set snapshots to private.
        :param client: Instance of the AWS boto3 client.
        :param snapshot_id: The id of the EBS snapshot.
        :param region: The region of the EBS snapshot.
        :type snapshot_id: str.
        :returns: Bool signaling success or failure
        :rtype: bool
        :raises: botocore.exceptions.ClientError
        """
        logging.info("Removing Public access by executing client.describe_snapshot_attribute")
        logging.info("Attribute = createVolumePermission")
        logging.info(f"SnapshotId={snapshot_id}")
        
        try:
        # Get the permissions of the snapshot, no exeption expected
           snapshot_permissions = client.describe_snapshot_attribute(
            Attribute='createVolumePermission',
            SnapshotId=snapshot_id
           ).get('CreateVolumePermissions')
        
           logging.info(f"permission={snapshot_permissions}")
        
           # if createVolumePermission has "Group":"all", remove it
           if snapshot_permissions:
               for permission in snapshot_permissions:
                   if 'all' in permission['Group']:
                       logging.info(f"Found Public Snapshot: {snapshot_id}")

                       # remove all from the groupname, no exception expected
                       client.modify_snapshot_attribute(
                           Attribute='createVolumePermission',
                           GroupNames=[
                            'all',
                           ],
                           OperationType='remove',
                           SnapshotId=snapshot_id,
                       )
                       logging.info(f"Public access removed from {snapshot_id}")
               return 0
           else:
               logging.info(f"Snapshot {snapshot_id} is not public, exiting")
               return 1

        except ClientError as state_err:
                error = state_err.response["Error"]["Code"]
                logging.error(f"Got Exception={error}")
                return 1
        except Exception as e:
               error = "Receiving other exceptions {0}".format(str(e))
               logging.error(error) 
               return 1
       
        
    def run(self, args):
        """Run the remediation job.
        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        client = boto3.client("ec2", region_name=params['region'])

        logging.debug(
            "acquired ec2 client and parsed params - starting remediation."
        )

        return self.remediate(client=client, **params)


if __name__ == "__main__":
    logging.info("ebs_private_snapshot.py called - running now")
    obj = EBSPrivateSnapshot()
    obj.run(sys.argv)
