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
from botocore.exceptions import ClientError
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

    def remove_port(self, client, security_group_rules, security_group_id, port):
        for rule in security_group_rules:
            if rule["IpProtocol"] == "tcp" and rule["IsEgress"] == False and "CidrIpv4" in rule and rule["CidrIpv4"] == "0.0.0.0/0" and rule["FromPort"] <= port and rule["ToPort"] >= port:
                if rule["FromPort"] == port and rule["ToPort"] == port:
                    logging.info("    executing client.revoke_security_group_ingress")
                    logging.info('      CidrIp="0.0.0.0/0"')
                    logging.info(f"      FromPort={port}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={port}")
                    client.revoke_security_group_ingress(
                        CidrIp="0.0.0.0/0",
                        FromPort=port,
                        GroupId=security_group_id,
                        IpProtocol="tcp",
                        ToPort=port,
                    )
                elif rule["FromPort"] < port and rule["ToPort"] == port:
                    logging.info("    executing client.modify_security_group_rules")
                    logging.info('      CidrIp="0.0.0.0/0"')
                    logging.info(f"      FromPort={rule['FromPort']}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={port - 1}")
                    client.modify_security_group_rules(
                        GroupId=security_group_id,
                        SecurityGroupRules=[
                            {
                                'SecurityGroupRuleId': rule["SecurityGroupRuleId"],
                                'SecurityGroupRule': {
                                    'IpProtocol': 'tcp',
                                    'FromPort': rule["FromPort"],
                                    'ToPort': port - 1,
                                    'CidrIpv4': '0.0.0.0/0'
                                }
                            }
                        ]
                    )
                elif rule["FromPort"] == port and rule["ToPort"] > port:
                    logging.info("    executing client.modify_security_group_rules")
                    logging.info('      CidrIp="0.0.0.0/0"')
                    logging.info(f"      FromPort={port + 1}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={rule['ToPort']}")
                    client.modify_security_group_rules(
                        GroupId=security_group_id,
                        SecurityGroupRules=[
                            {
                                'SecurityGroupRuleId': rule["SecurityGroupRuleId"],
                                'SecurityGroupRule': {
                                    'IpProtocol': 'tcp',
                                    'FromPort': port + 1,
                                    'ToPort': rule["ToPort"],
                                    'CidrIpv4': '0.0.0.0/0'
                                }
                            }
                        ]
                    )
                elif rule["FromPort"] < port and rule["ToPort"] > port:
                    logging.info("    executing client.modify_security_group_rules")
                    logging.info('      CidrIp="0.0.0.0/0"')
                    logging.info(f"      FromPort={rule['FromPort']}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={port - 1}")
                    client.modify_security_group_rules(
                        GroupId=security_group_id,
                        SecurityGroupRules=[
                            {
                                'SecurityGroupRuleId': rule["SecurityGroupRuleId"],
                                'SecurityGroupRule': {
                                    'IpProtocol': 'tcp',
                                    'FromPort': rule["FromPort"],
                                    'ToPort': port - 1,
                                    'CidrIpv4': '0.0.0.0/0'
                                }
                            }
                        ]
                    )

                    logging.info("    executing client.authorize_security_group_ingress")
                    logging.info('      CidrIp="0.0.0.0/0"')
                    logging.info(f"      FromPort={port + 1}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={rule['ToPort']}")
                    client.authorize_security_group_ingress(
                        CidrIp='0.0.0.0/0',
                        FromPort=port + 1,
                        GroupId=security_group_id,
                        IpProtocol='tcp',
                        ToPort=rule["ToPort"]
                    )
            elif rule["IpProtocol"] == "tcp" and rule["IsEgress"] == False and "CidrIpv6" in rule and rule["CidrIpv6"] == "::/0" and rule["FromPort"] <= port and rule["ToPort"] >= port:
                if rule["FromPort"] == port and rule["ToPort"] == port:
                    logging.info("    executing client.revoke_security_group_ingress")
                    logging.info(f"      FromPort={port}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info('      "Ipv6Ranges": [{"CidrIpv6": "::/0"}]')
                    logging.info(f"      ToPort={port}")
                    client.revoke_security_group_ingress(
                        GroupId=security_group_id,
                        IpPermissions=[
                            {
                                "FromPort": port,
                                "IpProtocol": "tcp",
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                                "ToPort": port,
                            },
                        ],
                    )
                elif rule["FromPort"] < port and rule["ToPort"] == port:
                    logging.info("    executing client.modify_security_group_rules")
                    logging.info('      CidrIpv6="::/0"')
                    logging.info(f"      FromPort={rule['FromPort']}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={port - 1}")
                    client.modify_security_group_rules(
                        GroupId=security_group_id,
                        SecurityGroupRules=[
                            {
                                'SecurityGroupRuleId': rule["SecurityGroupRuleId"],
                                'SecurityGroupRule': {
                                    'IpProtocol': 'tcp',
                                    'FromPort': rule["FromPort"],
                                    'ToPort': port - 1,
                                    'CidrIpv6': '::/0'
                                }
                            }
                        ]
                    )
                elif rule["FromPort"] == port and rule["ToPort"] > port:
                    logging.info("    executing client.modify_security_group_rules")
                    logging.info('      CidrIpv6="::/0"')
                    logging.info(f"      FromPort={port + 1}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={rule['ToPort']}")
                    client.modify_security_group_rules(
                        GroupId=security_group_id,
                        SecurityGroupRules=[
                            {
                                'SecurityGroupRuleId': rule["SecurityGroupRuleId"],
                                'SecurityGroupRule': {
                                    'IpProtocol': 'tcp',
                                    'FromPort': port + 1,
                                    'ToPort': rule["ToPort"],
                                    'CidrIpv6': '::/0'
                                }
                            }
                        ]
                    )
                elif rule["FromPort"] < port and rule["ToPort"] > port:
                    logging.info("    executing client.modify_security_group_rules")
                    logging.info('      CidrIpv6="::/0"')
                    logging.info(f"      FromPort={rule['FromPort']}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={port - 1}")
                    client.modify_security_group_rules(
                        GroupId=security_group_id,
                        SecurityGroupRules=[
                            {
                                'SecurityGroupRuleId': rule["SecurityGroupRuleId"],
                                'SecurityGroupRule': {
                                    'IpProtocol': 'tcp',
                                    'FromPort': rule["FromPort"],
                                    'ToPort': port - 1,
                                    'CidrIpv6': '::/0'
                                }
                            }
                        ]
                    )

                    logging.info("    executing client.authorize_security_group_ingress")
                    logging.info('      CidrIpv6="::/0"')
                    logging.info(f"      FromPort={port + 1}")
                    logging.info(f"      GroupId={security_group_id}")
                    logging.info('      IpProtocol="tcp"')
                    logging.info(f"      ToPort={rule['ToPort']}")
                    client.authorize_security_group_ingress(
                        GroupId=security_group_id,
                        IpPermissions=[
                            {
                                'FromPort': port + 1,
                                'IpProtocol': 'tcp',
                                'Ipv6Ranges': [
                                    {
                                        'CidrIpv6': '::/0',
                                    },
                                ],
                                'ToPort': rule["ToPort"]
                            },
                        ]
                    )

    def remediate(self, client, instance_id):
        """Block public access to port 22 of all security groups attached to an EC2 instance.

        :param client: Instance of the AWS boto3 client.
        :param instance_id: The ID of the EC2 instance.
        :type instance_id: str
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            port = 21
            security_groups = client.describe_instances(InstanceIds=[instance_id])[
                "Reservations"
            ][0]["Instances"][0]["SecurityGroups"]
            for sg_info in security_groups:
                security_group_id = sg_info["GroupId"]
                security_group_rules = client.describe_security_group_rules(
                    Filters=[
                        {
                            'Name': 'group-id',
                            'Values': [security_group_id]
                        },
                    ],
                    MaxResults=1000
                )
                print(security_group_rules)
                self.remove_port(client, security_group_rules["SecurityGroupRules"], security_group_id, port)
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
