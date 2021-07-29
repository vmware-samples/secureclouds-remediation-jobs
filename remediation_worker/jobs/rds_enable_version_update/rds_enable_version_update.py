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


class RDSUpgradMinorVersion:
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        :param payload: JSON string containing parameters sent to the remediation job.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)
        finding_info = notification_info.get("FindingInfo", None)

        database_id = finding_info.get("ObjectId", None)
        region = finding_info.get("Region", None)

        if database_id is None:
            logging.error("Missing parameters for 'DATABASE_ID'.")
            raise Exception("Missing parameters for 'DATABASE_ID'.")

        logging.info("parsed params")
        logging.info("  database_id: %s", database_id)
        logging.info("  region: %s", region)

        return {
            "database_id": database_id,
            "region": region
        }

    def remediate(self, client, database_id):
        """Enable automatic minor version upgrades. Any instance with this value
        disabled will be converted to true.
        :param client: Instance of the AWS boto3 client.
        :param database_id: The id of the RDS instanace.
        :returns: updates flag for RDS auto upgrade minor version
        """

        logging.info("Updating auto minor version upgrade for %s", database_id)

        # convert the RDS auto minor version flag to True
        try:
            logging.info("Setting AutoMinorVersionUpgrade to True")
            logging.info(f"DBInstanceIdentifier={database_id}")         
            client.modify_db_instance(
              DBInstanceIdentifier=database_id,
              AutoMinorVersionUpgrade=True,
              ApplyImmediately=True)
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
                        "RDS database %s is in an unavailable state.",
                        database_id
                    )
                    
                logging.error(
                        "Remediation RDS database %s failed",
                        database_id
                )
                return 1
        except Exception as e:
               error = "Receiving other exceptions {0} while changing RDS database {1} minor version upgrade".format(str(e), instance_id)
               logging.error(error) 
               return 1

        return 0

    def run(self, args):
        """Run the remediation job.
        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])
        client = boto3.client("rds", region_name=params['region'])

        logging.info(
            "acquired rds client and parsed params - starting remediation."
        )

        return self.remediate(client, params['database_id'])


if __name__ == "__main__":
    logging.info("rds_enable_version_update.py called - running now %s",
        sys.argv[0])
        
    obj = RDSUpgradMinorVersion()
    obj.run(sys.argv)
