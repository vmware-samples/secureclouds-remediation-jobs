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

from azure.mgmt.storage import StorageManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.storage.models import StorageAccountUpdateParameters

logging.basicConfig(level=logging.INFO)


class StorageAccountAllowHttpsTrafficOnly(object):
    def parse(self, payload):
        """Parse payload received from Remediation Service.

        :param payload: JSON string containing parameters received from the remediation service.
        :type payload: str.
        :returns: Dictionary of parsed parameters
        :rtype: dict
        :raises: KeyError, JSONDecodeError
        """
        remediation_entry = json.loads(payload)

        account_name = remediation_entry["notificationInfo"]["FindingInfo"]["ObjectId"]
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
        logging.info(f"  account_name: {account_name}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")

        return {
            "resource_group_name": resource_group_name,
            "account_name": account_name,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(self, client, resource_group_name, account_name):
        """Block public access to blob container

        :param client: Instance of the Azure NetworkManagementClient.
        :param resource_group_name: The name of the resource group to which the storage account belongs
        :param account_name: The name of the storage account. You must specify the
            account name in the request.
        :type resource_group_name: str.
        :type account_name: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """

        update_params = StorageAccountUpdateParameters(enable_https_traffic_only=True)

        # Allow only https traffic for the storage account
        logging.info("Enabling HTTPS only traffic for storage account")
        try:
            logging.info("    executing client.storage_accounts.update")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      account_name={account_name}")
            client.storage_accounts.update(
                resource_group_name=resource_group_name,
                account_name=account_name,
                parameters=update_params,
            )
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

        credentials = ServicePrincipalCredentials(
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            secret=os.environ.get("AZURE_CLIENT_SECRET"),
            tenant=os.environ.get("AZURE_TENANT_ID"),
        )

        client = StorageManagementClient(credentials, params["subscription_id"])
        return self.remediate(
            client, params["resource_group_name"], params["account_name"]
        )


if __name__ == "__main__":
    sys.exit(StorageAccountAllowHttpsTrafficOnly().run(sys.argv))
