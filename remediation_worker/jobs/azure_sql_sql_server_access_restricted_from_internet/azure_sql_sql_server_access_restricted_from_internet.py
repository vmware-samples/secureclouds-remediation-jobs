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
import os
import sys
import logging

from azure.mgmt.network import NetworkManagementClient
from azure.common.credentials import ServicePrincipalCredentials

logging.basicConfig(level=logging.INFO)

class SqlServerAccessRestrictedFromInternet(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: KeyError, JSONDecodeError
        """
        remediation_entry = json.loads(payload)

        security_group_name = remediation_entry["notificationInfo"]["FindingInfo"]["ObjectId"]
        region = remediation_entry["notificationInfo"]["FindingInfo"]["Region"]
        object_chain = remediation_entry["notificationInfo"]["FindingInfo"]["ObjectChain"]
        object_chain_dict = json.loads(object_chain)
        subscription_id = object_chain_dict["cloudAccountId"]

        properties = object_chain_dict["properties"]
        resource_group_name = ""
        for property in properties:
            if property["name"] == "ResourceGroup" and property["type"] == "string":
                resource_group_name = property["stringV"]
                break

        logging.info("parsed params")
        logging.info(f"  security_group: {security_group_name}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  resource_group_name: {resource_group_name}")
        logging.info(f"  region: {region}")

        return {
            "security_group_name": security_group_name,
            "resource_group_name": resource_group_name,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(self, client, resource_group_name, security_group_name):
        """Block public access to port 1433

        :param client: Instance of the Azure NetworkManagementClient.
        :param resource_group_name: The name of the resource group to which the security_group belongs
        :param security_group_name: The name of the security group. You must specify the
            security group name in the request.
        :type security_group_name: str.
        :type resource_group_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        port = 1433

        network_security_group = client.network_security_groups.get(
            resource_group_name=resource_group_name,
            network_security_group_name=security_group_name,
        )

        security_rules = network_security_group.security_rules

        for rule in security_rules:
            if (
                rule.access != "Allow"
                or rule.direction != "Inbound"
                or rule.source_address_prefix != "*"
            ):
                continue
            if rule.destination_port_range is not None:
                port_range = rule.destination_port_range
                if "-" in port_range:
                    new_ranges = self._find_and_remove_port([port_range], port)
                    if len(new_ranges) == 1:
                        rule.destination_port_range = new_ranges[0]
                    else:
                        rule.destination_port_range = None
                        rule.destination_port_ranges = new_ranges
                elif int(rule.destination_port_range) == port:
                    security_rules.remove(rule)
            else:
                port_ranges = rule.destination_port_ranges
                new_ranges = self._find_and_remove_port(port_ranges, port)
                rule.destination_port_ranges = new_ranges

        network_security_group.security_rules = security_rules

        # Revoke permission for port 1433
        logging.info("revoking permissions for port 1433")
        try:
            logging.info(
                "    executing client.network_security_groups.create_or_update"
            )
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      network_security_group_name={security_group_name}")
            client.network_security_groups.create_or_update(
                resource_group_name, security_group_name, network_security_group
            )
        except Exception as e:
            logging.error(f"{str(e)}")
            raise

        return 0

    def _find_and_remove_port(self, port_ranges, port):
        """Remove the port from the port range.

        :param port_ranges: port ranges to be updated.
        :param port: port to be removed
        :type port_ranges: list.
        :type port: int
        :returns: list of port_ranges
        """
        result = []
        for port_range in port_ranges:
            if "-" in port_range:
                boundaries = port_range.split("-")
                if int(boundaries[0]) <= port and int(boundaries[1]) >= port:
                    if int(boundaries[0]) == port:
                        new_range_start = port + 1
                        new_range_end = int(boundaries[1])
                        if new_range_start != new_range_end:
                            result.append(
                                str(new_range_start) + "-" + str(new_range_end)
                            )
                        else:
                            result.append(str(new_range_start))
                    elif int(boundaries[1]) == port:
                        new_range_start = int(boundaries[0])
                        new_range_end = port - 1
                        if new_range_start != new_range_end:
                            result.append(
                                str(new_range_start) + "-" + str(new_range_end)
                            )
                        else:
                            result.append(str(new_range_start))
                    else:
                        range1_start = int(boundaries[0])
                        range1_end = port - 1
                        range2_start = port + 1
                        range2_end = int(boundaries[1])

                        if range1_start != range1_end:
                            result.append(str(range1_start) + "-" + str(range1_end))
                        else:
                            result.append(str(range1_start))

                        if range2_start != range2_end:
                            result.append(str(range2_start) + "-" + str(range2_end))
                        else:
                            result.append(str(range2_start))
                else:
                    result.append(port_range)
            elif int(port_range) != port:
                result.append(port_range)
        return result

    def run(self, args):
        """Run the remediation job.

        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])

        credentials = ServicePrincipalCredentials(
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            secret=os.environ.get("AZURE_CLIENT_SECRET"),
            tenant=os.environ.get("AZURE_TENANT_ID"),
        )

        client = NetworkManagementClient(credentials, params["subscription_id"])
        return self.remediate(
            client, params["resource_group_name"], params["security_group_name"]
        )


if __name__ == "__main__":
    sys.exit(SqlServerAccessRestrictedFromInternet().run(sys.argv))
