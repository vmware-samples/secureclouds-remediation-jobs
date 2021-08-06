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
    logging.info(f(*args, **kwargs))


class SecurityGroupClosePort22(object):
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
            "security_group_id": payload_dict["notificationInfo"]["FindingInfo"][
                "ObjectId"
            ],
            "region": payload_dict["notificationInfo"]["FindingInfo"]["Region"],
        }

    def remediate(self, client, security_group_id):
        """Block public access to port 22 for both IPv4 and IPv6 by
        removing all the rules containing port 22 in the range.

        :param client: Instance of the AWS boto3 client.
        :param security_group_id: The ID of the security group. You must specify either the security group ID or the
            security group name in the request. For security groups in a nondefault VPC, you must specify the security
            group ID.
        :type security_group_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """

        port = 22
        try:
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
                    # Removes Ingress security group rule containing port 22 in the range with
                    # protocol 'tcp', source '0.0.0.0/0' or '::/0'
                    logging.info("    executing client.revoke_security_group_ingress")
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
        params = self.parse(args[1])
        client = boto3.client("ec2", region_name=params["region"])
        return self.remediate(client, params["security_group_id"])


if __name__ == "__main__":
    sys.exit(SecurityGroupClosePort22().run(sys.argv))
