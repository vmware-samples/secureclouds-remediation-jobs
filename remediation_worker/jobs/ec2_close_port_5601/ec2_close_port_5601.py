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


class EC2ClosePort5601(object):
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

    def check_if_port_range_exists(
        self, security_group_rules, port_range_list, from_port, to_port
    ):
        """Checks if the given port range already exists
        :param security_group_rules: Security group rules list.
        :param port_range_list: list of new or modified port ranges.
        :param from_port: From port.
        :param to_port: To port.
        :type security_group_rules: list
        :type port_range_list: list
        :type from_port: int
        :type to_port: int
        :returns: Boolean value indicating if the port range already exists.
        :rtype: bool
        """
        for rule in security_group_rules:
            if (
                rule["IpProtocol"] == "tcp"
                and rule["IsEgress"] is False
                and "CidrIpv4" in rule
                and rule["CidrIpv4"] == "0.0.0.0/0"
                and rule["FromPort"] == from_port
                and rule["ToPort"] == to_port
            ):
                return True
            elif (
                rule["IpProtocol"] == "tcp"
                and rule["IsEgress"] is False
                and "CidrIpv6" in rule
                and rule["CidrIpv6"] == "::/0"
                and rule["FromPort"] == from_port
                and rule["ToPort"] == to_port
            ):
                return True
        for port_range in port_range_list:
            if port_range[0] == from_port and port_range[1] == to_port:
                return True
        return False

    def delete_sg_rule(self, client, from_port, to_port, security_group_id, ip_type):
        """Deletes a specified security group rule
        :param security_group_id: Security group Id.
        :param ip_type: Ipv4 or Ipv6
        :param from_port: From port.
        :param to_port: To port.
        :type security_group_id: str
        :type ip_type: str
        :type from_port: int
        :type to_port: int
        :returns: None
        :rtype: None
        """
        logging.info("    executing client.revoke_security_group_ingress")
        logging.info(f"      FromPort={from_port}")
        logging.info(f"      GroupId={security_group_id}")
        logging.info('      IpProtocol="tcp"')
        logging.info(f"      ToPort={to_port}")
        if ip_type == "ipv4":
            logging.info('      CidrIp="0.0.0.0/0"')
            client.revoke_security_group_ingress(
                CidrIp="0.0.0.0/0",
                FromPort=from_port,
                GroupId=security_group_id,
                IpProtocol="tcp",
                ToPort=to_port,
            )
        elif ip_type == "ipv6":
            logging.info('      "Ipv6Ranges": [{"CidrIpv6": "::/0"}]')
            client.revoke_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        "FromPort": from_port,
                        "IpProtocol": "tcp",
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        "ToPort": to_port,
                    },
                ],
            )
        else:
            return

    def modify_sg_rules(
        self,
        client,
        from_port,
        to_port,
        security_group_id,
        security_group_rule_id,
        ip_type,
    ):
        """Modifies a specified security group rule
        :param security_group_id: Security group Id.
        :param security_group_rule_id: Security group rule Id
        :param ip_type: Ipv4 or Ipv6
        :param from_port: From port.
        :param to_port: To port.
        :type security_group_id: str
        :type security_group_rule_id: str
        :type ip_type: str
        :type from_port: int
        :type to_port: int
        :returns: None
        :rtype: None
        """
        if ip_type == "ipv4":
            security_group_rules = [
                {
                    "SecurityGroupRuleId": security_group_rule_id,
                    "SecurityGroupRule": {
                        "IpProtocol": "tcp",
                        "FromPort": from_port,
                        "ToPort": to_port,
                        "CidrIpv4": "0.0.0.0/0",
                    },
                }
            ]
        elif ip_type == "ipv6":
            security_group_rules = [
                {
                    "SecurityGroupRuleId": security_group_rule_id,
                    "SecurityGroupRule": {
                        "IpProtocol": "tcp",
                        "FromPort": from_port,
                        "ToPort": to_port,
                        "CidrIpv6": "::/0",
                    },
                }
            ]
        else:
            return
        logging.info("    executing client.modify_security_group_rules")
        logging.info(f"      FromPort={from_port}")
        logging.info(f"      GroupId={security_group_id}")
        logging.info('      IpProtocol="tcp"')
        logging.info(f"      ToPort={to_port}")
        client.modify_security_group_rules(
            GroupId=security_group_id, SecurityGroupRules=security_group_rules
        )

    def remove_port(
        self, client, security_group_rules, security_group_id, port, port_range_list
    ):
        """Removes the given port from the security group rules
        :param security_group_rules: Security group rules list.
        :param security_group_id: Security group Id.
        :param port_range_list: list of new or modified port ranges.
        :param port: Port no. which is to be removed.
        :type security_group_rules: list
        :type security_group_id: str
        :type port_range_list: list
        :type port: int
        :returns: None
        :rtype: None
        """
        for rule in security_group_rules:
            # For Ipv4
            if (
                rule["IpProtocol"] == "tcp"
                and rule["IsEgress"] is False
                and "CidrIpv4" in rule
                and rule["CidrIpv4"] == "0.0.0.0/0"
                and rule["FromPort"] <= port
                and rule["ToPort"] >= port
            ):
                # If FromPort and ToPort both are equal to the port no. which is to be
                # removed then delete the security group rule
                if rule["FromPort"] == port and rule["ToPort"] == port:
                    self.delete_sg_rule(client, port, port, security_group_id, "ipv4")

                # If FromPort is less than and ToPort is equal to the port no. which is to be
                # by removing the port from the range
                elif rule["FromPort"] < port and rule["ToPort"] == port:
                    if not self.check_if_port_range_exists(
                        security_group_rules,
                        port_range_list,
                        rule["FromPort"],
                        port - 1,
                    ):
                        self.modify_sg_rules(
                            client,
                            rule["FromPort"],
                            port - 1,
                            security_group_id,
                            rule["SecurityGroupRuleId"],
                            "ipv4",
                        )
                        port_range = (rule["FromPort"], port - 1)
                        port_range_list.append(port_range)

                    else:
                        self.delete_sg_rule(
                            client,
                            rule["FromPort"],
                            rule["ToPort"],
                            security_group_id,
                            "ipv4",
                        )

                # If FromPort is equal and ToPort is greater that the port no. which is to be removed then modify the security group rule
                # by removing the port from the range
                elif rule["FromPort"] == port and rule["ToPort"] > port:
                    if not self.check_if_port_range_exists(
                        security_group_rules, port_range_list, port + 1, rule["ToPort"]
                    ):
                        self.modify_sg_rules(
                            client,
                            port + 1,
                            rule["ToPort"],
                            security_group_id,
                            rule["SecurityGroupRuleId"],
                            "ipv4",
                        )
                        port_range = (port + 1, rule["ToPort"])
                        port_range_list.append(port_range)

                    else:
                        self.delete_sg_rule(
                            client,
                            rule["FromPort"],
                            rule["ToPort"],
                            security_group_id,
                            "ipv4",
                        )

                # If FromPort is less than and ToPort is greater that the port no. which is to be
                # removed then modify the security group rule by removing the port from the range
                elif rule["FromPort"] < port and rule["ToPort"] > port:
                    if not self.check_if_port_range_exists(
                        security_group_rules, port_range_list, port + 1, rule["ToPort"]
                    ):
                        logging.info(
                            "    executing client.authorize_security_group_ingress"
                        )
                        logging.info('      CidrIp="0.0.0.0/0"')
                        logging.info(f"      FromPort={port + 1}")
                        logging.info(f"      GroupId={security_group_id}")
                        logging.info('      IpProtocol="tcp"')
                        logging.info(f"      ToPort={rule['ToPort']}")
                        client.authorize_security_group_ingress(
                            CidrIp="0.0.0.0/0",
                            FromPort=port + 1,
                            GroupId=security_group_id,
                            IpProtocol="tcp",
                            ToPort=rule["ToPort"],
                        )
                        port_range = (port + 1, rule["ToPort"])
                        port_range_list.append(port_range)

                    if not self.check_if_port_range_exists(
                        security_group_rules,
                        port_range_list,
                        rule["FromPort"],
                        port - 1,
                    ):
                        self.modify_sg_rules(
                            client,
                            rule["FromPort"],
                            port - 1,
                            security_group_id,
                            rule["SecurityGroupRuleId"],
                            "ipv4",
                        )
                        port_range = (rule["FromPort"], port - 1)
                        port_range_list.append(port_range)

                    else:
                        self.delete_sg_rule(
                            client,
                            rule["FromPort"],
                            rule["ToPort"],
                            security_group_id,
                            "ipv4",
                        )

            # For Ipv6
            elif (
                rule["IpProtocol"] == "tcp"
                and rule["IsEgress"] is False
                and "CidrIpv6" in rule
                and rule["CidrIpv6"] == "::/0"
                and rule["FromPort"] <= port
                and rule["ToPort"] >= port
            ):
                if rule["FromPort"] == port and rule["ToPort"] == port:
                    self.delete_sg_rule(client, port, port, security_group_id, "ipv6")

                elif rule["FromPort"] < port and rule["ToPort"] == port:
                    if not self.check_if_port_range_exists(
                        security_group_rules,
                        port_range_list,
                        rule["FromPort"],
                        port - 1,
                    ):
                        self.modify_sg_rules(
                            client,
                            rule["FromPort"],
                            port - 1,
                            security_group_id,
                            rule["SecurityGroupRuleId"],
                            "ipv6",
                        )
                        port_range = (rule["FromPort"], port - 1)
                        port_range_list.append(port_range)

                    else:
                        self.delete_sg_rule(
                            client,
                            rule["FromPort"],
                            rule["ToPort"],
                            security_group_id,
                            "ipv6",
                        )

                elif rule["FromPort"] == port and rule["ToPort"] > port:
                    if not self.check_if_port_range_exists(
                        security_group_rules, port_range_list, port + 1, rule["ToPort"]
                    ):
                        self.modify_sg_rules(
                            client,
                            port + 1,
                            rule["ToPort"],
                            security_group_id,
                            rule["SecurityGroupRuleId"],
                            "ipv6",
                        )
                        port_range = (port + 1, rule["ToPort"])
                        port_range_list.append(port_range)

                    else:
                        self.delete_sg_rule(
                            client,
                            rule["FromPort"],
                            rule["ToPort"],
                            security_group_id,
                            "ipv6",
                        )

                elif rule["FromPort"] < port and rule["ToPort"] > port:
                    if not self.check_if_port_range_exists(
                        security_group_rules, port_range_list, port + 1, rule["ToPort"]
                    ):
                        logging.info(
                            "    executing client.authorize_security_group_ingress"
                        )
                        logging.info('      CidrIpv6="::/0"')
                        logging.info(f"      FromPort={port + 1}")
                        logging.info(f"      GroupId={security_group_id}")
                        logging.info('      IpProtocol="tcp"')
                        logging.info(f"      ToPort={rule['ToPort']}")
                        client.authorize_security_group_ingress(
                            GroupId=security_group_id,
                            IpPermissions=[
                                {
                                    "FromPort": port + 1,
                                    "IpProtocol": "tcp",
                                    "Ipv6Ranges": [{"CidrIpv6": "::/0",},],
                                    "ToPort": rule["ToPort"],
                                },
                            ],
                        )
                        port_range = (port + 1, rule["ToPort"])
                        port_range_list.append(port_range)

                    if not self.check_if_port_range_exists(
                        security_group_rules,
                        port_range_list,
                        rule["FromPort"],
                        port - 1,
                    ):
                        self.modify_sg_rules(
                            client,
                            rule["FromPort"],
                            port - 1,
                            security_group_id,
                            rule["SecurityGroupRuleId"],
                            "ipv6",
                        )
                        port_range = (rule["FromPort"], port - 1)
                        port_range_list.append(port_range)

                    else:
                        self.delete_sg_rule(
                            client,
                            rule["FromPort"],
                            rule["ToPort"],
                            security_group_id,
                            "ipv6",
                        )

    def remediate(self, client, instance_id):
        """Block public access to port 5601 of all security groups attached to an EC2 instance.

        :param client: Instance of the AWS boto3 client.
        :param instance_id: The ID of the EC2 instance.
        :type instance_id: str
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: botocore.exceptions.ClientError
        """
        try:
            port = 5601
            logging.info("    executing client.describe_instances")
            logging.info(f"    InstanceId: {instance_id}")
            security_groups = client.describe_instances(InstanceIds=[instance_id])[
                "Reservations"
            ][0]["Instances"][0]["SecurityGroups"]
            for sg_info in security_groups:
                port_range_list = []
                security_group_id = sg_info["GroupId"]
                logging.info("    executing client.describe_security_group_rules")
                logging.info(f"    group-id: {security_group_id}")
                security_group_rules = client.describe_security_group_rules(
                    Filters=[{"Name": "group-id", "Values": [security_group_id]},],
                    MaxResults=1000,
                )
                self.remove_port(
                    client,
                    security_group_rules["SecurityGroupRules"],
                    security_group_id,
                    port,
                    port_range_list,
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
    obj = EC2ClosePort5601()
    obj.run(sys.argv)
