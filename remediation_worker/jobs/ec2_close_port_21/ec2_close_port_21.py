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

from __future__ import annotations
import json
import logging
import sys

import boto3

logging.basicConfig(level=logging.INFO)


class EC2ClosePort21(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: Exception, JSONDecodeError
        """
        remediation_entry = json.loads(payload)
        notification_info = remediation_entry.get("notificationInfo", None)

        finding_info = notification_info.get("FindingInfo", None)
        instance_id = finding_info.get("ObjectId", None)

        if instance_id is None:
            logging.error("Missing parameters for 'payload.notificationInfo.ObjectId'.")
            raise Exception(
                "Missing parameters for 'payload.notificationInfo.ObjectId'."
            )

        region = finding_info.get("Region", None)
        if region is None:
            logging.warning("no region specified - defaulting to us-east-1")
            region = "us-east-1"

        logging.info("parsed params")
        logging.info(f"  instance_id: {instance_id}")
        logging.info(f"  region: {region}")

        return {"instance_id": instance_id}, region

    def remediate(self, client, instance_id):
        """Block public access to port 21 of all security groups attached to an EC2 instance
        by removing all the rules with port 21 in the port range
        :param client: Instance of the AWS boto3 client.
        :param instance_id: The ID of the EC2 instance.
        :type instance_id: str
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            port = 21
            logging.info("    executing client.describe_instances")
            logging.info(f"    InstanceId: {instance_id}")
            # Extract security group Id
            security_groups = client.describe_instances(InstanceIds=[instance_id])[
                "Reservations"
            ][0]["Instances"][0]["SecurityGroups"]
            for sg_info in security_groups:
                security_group_id = sg_info["GroupId"]
                logging.info("    executing client.describe_security_group_rules")
                logging.info(f"    group-id: {security_group_id}")
                # List all the security group rules
                security_group_rules = client.describe_security_group_rules(
                    Filters=[{"Name": "group-id", "Values": [security_group_id]},],
                    MaxResults=1000,
                )
                for rule in security_group_rules["SecurityGroupRules"]:
                    if (
                        rule["IpProtocol"] == "tcp"
                        and rule["IsEgress"] is False
                        and rule["FromPort"] <= port
                        and rule["ToPort"] >= port
                        and (
                            ("CidrIpv4" in rule and rule["CidrIpv4"] == "0.0.0.0/0")
                            or ("CidrIpv6" in rule and rule["CidrIpv6"] == "::/0")
                        )
                    ):
                        # Removes Ingress security group rule containing port 21 in the range with
                        # protocol 'tcp', source '0.0.0.0/0' or '::/0'
                        logging.info(
                            "    executing client.revoke_security_group_ingress"
                        )
                        logging.info(f"    GroupId: {security_group_id}")
                        logging.info(
                            f"    SecurityGroupRuleIds: {rule['SecurityGroupRuleId']}"
                        )
                        client.revoke_security_group_ingress(
                            GroupId=security_group_id,
                            SecurityGroupRuleIds=[rule["SecurityGroupRuleId"]],
                        )
                logging.info("successfully executed remediation")
        except Exception as e:
            logging.error(f"{str(e)}")
        return 0

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params, region = self.parse(args[1])
        client = boto3.client("ec2", region_name=region)
        logging.info("acquired ec2 client and parsed params - starting remediation")
        rc = self.remediate(client=client, **params)
        return rc


if __name__ == "__main__":
    logging.info(f"{sys.argv[0]} called - running now")
    obj = EC2ClosePort21()
    obj.run(sys.argv)
