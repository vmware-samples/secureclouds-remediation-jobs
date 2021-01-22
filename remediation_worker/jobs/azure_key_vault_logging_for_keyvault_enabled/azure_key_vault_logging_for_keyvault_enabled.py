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

from azure.identity import ClientSecretCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import (
    StorageAccountCreateParameters,
    NetworkRuleSet,
    Sku,
    SkuName,
    SkuTier,
    DefaultAction,
)
from azure.mgmt.monitor.models import (
    DiagnosticSettingsResource,
    LogSettings,
    RetentionPolicy,
)

logging.basicConfig(level=logging.INFO)


def generate_name(prefix):
    prefix = "".join(i for i in prefix if i.islower() or i.isdigit())
    if len(prefix) >= 12:
        prefix = str(prefix[:11])
    result_str = prefix + "keyvaultlogs"
    return result_str


def create_storage_account(
    resource_group_name, name, region, storage_client,
):
    create_params = StorageAccountCreateParameters(
        location=region,
        sku=Sku(name=SkuName.STANDARD_LRS, tier=SkuTier.STANDARD),
        kind="StorageV2",
        enable_https_traffic_only=True,
        network_rule_set=NetworkRuleSet(default_action=DefaultAction.DENY),
    )
    poller = storage_client.storage_accounts.begin_create(
        resource_group_name=resource_group_name,
        account_name=name,
        parameters=create_params,
    )
    return poller.result()


class EnableKeyVaultLogging(object):
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
        logging.info(f"  account_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")

        return {
            "resource_group_name": resource_group_name,
            "key_vault_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(
        self,
        keyvault_client,
        monitor_client,
        storage_client,
        resource_group_name,
        key_vault_name,
        region,
    ):
        """Enable key vault logging
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param storage_client: Instance of the Azure StorageManagementClient.
        :param monitor_client: Instance of the Azure MonitorClient.
        :param resource_group_name: The name of the resource group to which the storage account belongs.
        :param key_vault_name: The name of the key vault.
        :param region: The region in which the key vault is present.
        :type resource_group_name: str.
        :type key_vault_name: str.
        :type region: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """
        key_vault = keyvault_client.vaults.get(
            resource_group_name=resource_group_name, vault_name=key_vault_name,
        )
        try:
            stg_name = generate_name(key_vault_name)
            logging.info("    Creating a Storage Account")
            logging.info("    executing client_storage.storage_accounts.begin_create")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      account_name={stg_name}")
            stg_account = create_storage_account(
                resource_group_name, stg_name, region, storage_client
            )
            log = LogSettings(
                category="AuditEvent",
                enabled=True,
                retention_policy=RetentionPolicy(enabled=True, days=180),
            )

            logging.info("    Creating a Diagnostic setting for key vault logs")
            logging.info(
                "    executing monitor_client.diagnostic_settings.create_or_update"
            )
            logging.info(f"      resource_uri={key_vault.id}")
            logging.info(f"      name={key_vault_name}")

            monitor_client.diagnostic_settings.create_or_update(
                resource_uri=key_vault.id,
                name=key_vault_name,
                parameters=DiagnosticSettingsResource(
                    storage_account_id=stg_account.id, logs=[log],
                ),
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

        credentials = ClientSecretCredential(
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            client_secret=os.environ.get("AZURE_CLIENT_SECRET"),
            tenant_id=os.environ.get("AZURE_TENANT_ID"),
        )
        storage_client = StorageManagementClient(
            credentials, params["subscription_id"]
        )
        keyvault_client = KeyVaultManagementClient(
            credentials, params["subscription_id"]
        )
        monitor_client = MonitorClient(credentials, params["subscription_id"])
        return self.remediate(
            keyvault_client,
            monitor_client,
            storage_client,
            params["resource_group_name"],
            params["key_vault_name"],
            params["region"],
        )


if __name__ == "__main__":
    sys.exit(EnableKeyVaultLogging().run(sys.argv))
