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
import time

from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import DdosProtectionPlanListResult, SubResource
from azure.identity import ClientSecretCredential
from azure.core.paging import ItemPaged
from typing import List

logging.basicConfig(level=logging.INFO)


class VirtualNetworkEnableDdosProtection(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.
        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: KeyError, JSONDecodeError
        """
        remediation_entry = json.loads(payload)

        object_id = remediation_entry["notificationInfo"]["FindingInfo"]["ObjectId"]

        region = remediation_entry["notificationInfo"]["FindingInfo"]["Region"]

        object_chain = remediation_entry["notificationInfo"]["FindingInfo"][
            "ObjectChain"
        ]

        object_chain_dict = json.loads(object_chain)
        subscription_id = object_chain_dict["cloudAccountId"]

        properties = object_chain_dict["properties"]
        resource_group_name = ""
        for property in properties:
            if property["name"] == "ResourceGroup" and property["type"] == "string":
                resource_group_name = property["stringV"]
                break

        logging.info("parsed params")
        logging.info(f"  resource_group_name: {resource_group_name}")
        logging.info(f"  virtual_network_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")
        return {
            "resource_group_name": resource_group_name,
            "virtual_network_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(
        self, client, resource_group_name, virtual_network_name, subscription_id
    ):
        """Enable DDos protection for a Virtual Network
        :param client: Instance of the Azure NetworkManagementClient.
        :param resource_group_name: The name of the resource group to which the virtual network belongs.
        :param virtual_network_name: The name of the Virtual Network.
        :param subscription_id: The Subscription ID of the user.
        :type resource_group_name: str.
        :type virtual_network_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        ddos_plans_paged: ItemPaged[
            DdosProtectionPlanListResult
        ] = client.ddos_protection_plans.list()
        ddos_plans_list: List[dict] = list(ddos_plans_paged)
        number_of_ddos: int = len(ddos_plans_list)

        if number_of_ddos > 0:
            resource_id = ddos_plans_list[0].id
            logging.info(
                f"      Resource ID of Azure DDos Protection Plan={resource_id}"
            )
        else:
            logging.error(
                f"     Azure cloud user with subscription ID: {subscription_id} has no active Azure DDos protection plan available"
            )
            return 1

        virtual_network = client.virtual_networks.get(
            resource_group_name=resource_group_name,
            virtual_network_name=virtual_network_name,
        )

        # Enabling DDoS Protection
        virtual_network.enable_ddos_protection = True

        updated_SubResource = SubResource(id=resource_id)

        virtual_network.ddos_protection_plan = updated_SubResource

        logging.info("Enabling DDos protection for Virtual Network")
        try:
            logging.info("    executing client.virtual_networks.begin_create_or_update")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      virtual_network_name={virtual_network_name}")

            poller = client.virtual_networks.begin_create_or_update(
                resource_group_name=resource_group_name,
                virtual_network_name=virtual_network_name,
                parameters=virtual_network,
            )
            while not poller.done():
                time.sleep(5)
                status = poller.status()
                logging.info(f"The remediation job status: {status}")
            poller.result()
        except Exception as e:
            logging.error(f"{str(e)}")
            raise
        return 0

    def run(self, args):
        """Run the remediation job.
        :param args: List of arguments provided to the job.
        :type args: list.
        :returns: int
        """
        params = self.parse(args[1])

        credentials = ClientSecretCredential(
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            client_secret=os.environ.get("AZURE_CLIENT_SECRET"),
            tenant_id=os.environ.get("AZURE_TENANT_ID"),
        )

        client = NetworkManagementClient(credentials, params["subscription_id"])
        return self.remediate(
            client,
            params["resource_group_name"],
            params["virtual_network_name"],
            params["subscription_id"],
        )


if __name__ == "__main__":
    sys.exit(VirtualNetworkEnableDdosProtection().run(sys.argv))
