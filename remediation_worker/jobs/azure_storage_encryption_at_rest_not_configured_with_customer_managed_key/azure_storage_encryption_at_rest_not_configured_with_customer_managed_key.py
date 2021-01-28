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
import datetime
from dateutil import parser as date_parse

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorClient
from azure.keyvault.keys import KeyClient
from azure.identity import ClientSecretCredential
from azure.graphrbac import GraphRbacManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.storage.models import (
    StorageAccountUpdateParameters,
    Encryption,
    KeySource,
    KeyVaultProperties,
    Identity,
)
from azure.mgmt.keyvault.models import (
    VaultCreateOrUpdateParameters,
    VaultProperties,
    Sku,
    AccessPolicyEntry,
    Permissions,
    KeyPermissions,
)
from azure.mgmt.monitor.models import (
    DiagnosticSettingsResource,
    LogSettings,
    RetentionPolicy,
)

logging.basicConfig(level=logging.INFO)


def generate_key_vault_name(prefix):
    if len(prefix) >= 15:
        prefix = str(prefix[:14])
    result_str = prefix + "-keyvault"
    return result_str


class StorageAccountNotEncryptedWithCmk(object):
    def create_key_vault(
        self,
        keyvault_client,
        resource_group_name,
        key_vault_name,
        region,
        tenant_id,
        app_object_id,
        stg_principal_id,
    ):
        access_policy_storage_account = AccessPolicyEntry(
            tenant_id=tenant_id,
            object_id=stg_principal_id,
            permissions=Permissions(
                keys=[
                    KeyPermissions.GET,
                    KeyPermissions.UNWRAP_KEY,
                    KeyPermissions.WRAP_KEY,
                ],
            ),
        )
        access_policy_app = AccessPolicyEntry(
            tenant_id=tenant_id,
            object_id=app_object_id,
            permissions=Permissions(
                keys=[
                    KeyPermissions.GET,
                    KeyPermissions.LIST,
                    KeyPermissions.CREATE,
                    KeyPermissions.UPDATE,
                    KeyPermissions.DELETE,
                    KeyPermissions.BACKUP,
                    KeyPermissions.RESTORE,
                    KeyPermissions.RECOVER,
                ],
            ),
        )
        key_vault_properties = VaultCreateOrUpdateParameters(
            location=region,
            properties=VaultProperties(
                tenant_id=tenant_id,
                sku=Sku(family="A", name="standard",),
                access_policies=[access_policy_storage_account, access_policy_app],
                soft_delete_retention_in_days=90,
                enabled_for_disk_encryption=False,
                enabled_for_deployment=False,
                enabled_for_template_deployment=False,
                enable_soft_delete=True,
                enable_purge_protection=True,
            ),
        )
        vault = keyvault_client.vaults.begin_create_or_update(
            resource_group_name=resource_group_name,
            vault_name=key_vault_name,
            parameters=key_vault_properties,
        ).result()
        return vault

    def create_key(self, credential, key_vault_name):
        d = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
        date = datetime.datetime.strptime(
            d[0:19], "%Y-%m-%dT%H:%M:%S"
        ) + datetime.timedelta(days=180)
        expires_on = date_parse.parse(
            date.replace(microsecond=0, tzinfo=datetime.timezone.utc).isoformat()
        )
        key_client = KeyClient(
            vault_url=f"https://{key_vault_name}.vault.azure.net/",
            credential=credential,
        )
        rsa_key_name = key_vault_name + "-key"
        rsa_key = key_client.create_rsa_key(
            rsa_key_name, size=2048, expires_on=expires_on, enabled=True
        )
        return rsa_key

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
            "account_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def remediate(
        self,
        monitor_client,
        graph_client,
        storage_client,
        keyvault_client,
        client_id,
        tenant_id,
        credentials,
        resource_group_name,
        account_name,
        region,
    ):
        """Configure Storage Account with Customer Managed Key
        :param storage_client: Instance of the Azure StorageManagementClient.
        :param graph_client: Instance of the AzureGraphRbacManagementClient.
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param client_id: Azure Client ID.
        :param tenant_id: Azure Tenant ID.
        :param resource_group_name: The name of the resource group to which the storage account belongs.
        :param account_name: The name of the storage account.
        :param region: Region in which the storage account belongs.
        :type resource_group_name: str.
        :type account_name: str.
        :type region: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """
        try:
            app_details = graph_client.applications.get_service_principals_id_by_app_id(
                application_id=client_id
            )
            app_object_id = app_details.value

            stg_acc = storage_client.storage_accounts.get_properties(
                resource_group_name=resource_group_name, account_name=account_name,
            )
            if stg_acc.identity is None:

                logging.info(
                    f"Assigning Identity to the Storage Account {account_name}"
                )
                logging.info("executing storage_client.storage_accounts.update")
                logging.info(f"      resource_group_name={resource_group_name}")
                logging.info(f"      account_name={account_name}")

                updated_stg_acc = storage_client.storage_accounts.update(
                    resource_group_name=resource_group_name,
                    account_name=account_name,
                    parameters=StorageAccountUpdateParameters(
                        identity=Identity(type="SystemAssigned")
                    ),
                )

                stg_principal_id = updated_stg_acc.identity.principal_id
            else:
                stg_principal_id = stg_acc.identity.principal_id

            key_vault_name = generate_key_vault_name(account_name)

            logging.info("creating a key vault")
            logging.info("executing keyvault_client.vaults.begin_create_or_update")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      vault_name={key_vault_name}")

            key_vault = self.create_key_vault(
                keyvault_client,
                resource_group_name,
                key_vault_name,
                region,
                tenant_id,
                app_object_id,
                stg_principal_id,
            )
            logging.info("creating a key")
            key = self.create_key(credentials, key_vault_name)

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
                    storage_account_id=stg_acc.id, logs=[log],
                ),
            )

            logging.info("executing storage_client.storage_accounts.update")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      account_name={account_name}")

            storage_client.storage_accounts.update(
                resource_group_name=resource_group_name,
                account_name=account_name,
                parameters=StorageAccountUpdateParameters(
                    encryption=Encryption(
                        key_source=KeySource.MICROSOFT_KEYVAULT,
                        key_vault_properties=KeyVaultProperties(
                            key_name=key.name,
                            key_vault_uri=key_vault.properties.vault_uri,
                        ),
                    ),
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
        client_id = os.environ.get("AZURE_CLIENT_ID")
        client_secret = os.environ.get("AZURE_CLIENT_SECRET")
        tenant_id = os.environ.get("AZURE_TENANT_ID")

        credential = ClientSecretCredential(
            client_id=client_id, client_secret=client_secret, tenant_id=tenant_id,
        )

        credentials = ServicePrincipalCredentials(
            client_id=client_id,
            secret=client_secret,
            tenant=tenant_id,
            resource="https://graph.windows.net",
        )

        storage_client = StorageManagementClient(credential, params["subscription_id"])
        keyvault_client = KeyVaultManagementClient(
            credential, params["subscription_id"]
        )
        graph_client = GraphRbacManagementClient(credentials, tenant_id, base_url=None)
        monitor_client = MonitorClient(credential, params["subscription_id"])
        return self.remediate(
            monitor_client,
            graph_client,
            storage_client,
            keyvault_client,
            client_id,
            tenant_id,
            credential,
            params["resource_group_name"],
            params["account_name"],
            params["region"],
        )


if __name__ == "__main__":
    sys.exit(StorageAccountNotEncryptedWithCmk().run(sys.argv))
