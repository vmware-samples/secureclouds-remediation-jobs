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

from typing import List
from azure.core.paging import ItemPaged
from azure.keyvault.keys import KeyClient
from azure.mgmt.monitor import MonitorClient
from azure.identity import ClientSecretCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.graphrbac import GraphRbacManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.storage.models import (
    StorageAccountCreateParameters,
    NetworkRuleSet,
    SkuName,
    SkuTier,
    DefaultAction,
    Identity,
    StorageAccountListResult,
    BlobServiceProperties,
    DeleteRetentionPolicy,
    Encryption,
    KeySource,
    KeyVaultProperties,
    StorageAccountUpdateParameters,
)
from azure.mgmt.monitor.models import (
    DiagnosticSettingsResource,
    LogSettings,
    RetentionPolicy,
)
from azure.mgmt.keyvault.models import (
    VaultCreateOrUpdateParameters,
    VaultProperties,
    Sku,
    AccessPolicyEntry,
    Permissions,
    KeyPermissions,
    VaultListResult,
    AccessPolicyUpdateKind,
    VaultAccessPolicyParameters,
    VaultAccessPolicyProperties,
)

logging.basicConfig(level=logging.INFO)


def generate_name(region, subscription_id, resource_group_name):
    random_str = "".join(i for i in subscription_id if i.islower() or i.isdigit())
    subscription_id = random_str[:5]
    random_str = "".join(i for i in region if i.islower() or i.isdigit())
    region = random_str[-6:]
    random_str = "".join(i for i in resource_group_name if i.islower() or i.isdigit())
    resource_group_name = random_str[-5:]
    result_str = "chss" + subscription_id + resource_group_name + region + "logs"
    return result_str


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

    def create_storage_account(
        self, resource_group_name, name, region, storage_client,
    ):
        from azure.mgmt.storage.models import Sku

        create_params = StorageAccountCreateParameters(
            location=region,
            sku=Sku(name=SkuName.STANDARD_LRS, tier=SkuTier.STANDARD),
            identity=Identity(type="SystemAssigned"),
            kind="StorageV2",
            enable_https_traffic_only=True,
            network_rule_set=NetworkRuleSet(default_action=DefaultAction.DENY),
            tags={"Created By": "CHSS"},
        )
        stg_account = storage_client.storage_accounts.begin_create(
            resource_group_name=resource_group_name,
            account_name=name,
            parameters=create_params,
        ).result()

        storage_client.blob_services.set_service_properties(
            resource_group_name=resource_group_name,
            account_name=name,
            parameters=BlobServiceProperties(
                delete_retention_policy=DeleteRetentionPolicy(enabled=True, days=7)
            ),
        )
        return stg_account

    def update_storage_account_encryption(
        self, storage_client, resource_group_name, stg_name, key_name, vault_uri
    ):
        logging.info("    Encrypting Storage Account with Customer Managed Key")
        logging.info("    executing storage_client.storage_accounts.update")
        logging.info(f"      resource_group_name={resource_group_name}")
        logging.info(f"      account_name={stg_name}")
        logging.info(f"      key_vault_uri={vault_uri}")
        logging.info(f"      key_name={key_name}")
        storage_client.storage_accounts.update(
            resource_group_name=resource_group_name,
            account_name=stg_name,
            parameters=StorageAccountUpdateParameters(
                encryption=Encryption(
                    key_source=KeySource.MICROSOFT_KEYVAULT,
                    key_vault_properties=KeyVaultProperties(
                        key_name=key_name, key_vault_uri=vault_uri,
                    ),
                ),
            ),
        )

    def check_stg_account(self, storage_client, region, name, resource_group_name):
        storage_accounts_paged: ItemPaged[
            StorageAccountListResult
        ] = storage_client.storage_accounts.list()
        storage_accounts_list: List[dict] = list(storage_accounts_paged)
        for stg_account in storage_accounts_list:
            stg_id = stg_account.id
            stg_components = stg_id.split("/")
            resource_grp = stg_components[4]
            if (
                stg_account.name == name
                and stg_account.location == region
                and resource_grp == resource_group_name
            ):
                return stg_account
        return None

    def check_key_vault(self, keyvault_client, region, name, resource_group_name):
        key_vault_paged: ItemPaged[
            VaultListResult
        ] = keyvault_client.vaults.list_by_subscription()
        key_vault_list: List[dict] = list(key_vault_paged)
        for key_vault in key_vault_list:
            key_vault_id = key_vault.id
            key_vault_components = key_vault_id.split("/")
            resource_grp = key_vault_components[4]
            if (
                key_vault.name == name
                and key_vault.location == region
                and resource_grp == resource_group_name
            ):
                return key_vault
        return None

    def create_diagnostic_setting(
        self, monitor_client, key_vault_id, key_vault_name, stg_account_id, log
    ):
        logging.info("    Creating a Diagnostic setting for key vault logs")
        logging.info(
            "    executing monitor_client.diagnostic_settings.create_or_update"
        )
        logging.info(f"      resource_uri={key_vault_id}")
        logging.info(f"      name={key_vault_name}")
        monitor_client.diagnostic_settings.create_or_update(
            resource_uri=key_vault_id,
            name=key_vault_name,
            parameters=DiagnosticSettingsResource(
                storage_account_id=stg_account_id, logs=[log],
            ),
        )

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
            tags={"CreatedBy": "CHSS"},
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
        logging.info("creating a key vault")
        logging.info("executing keyvault_client.vaults.begin_create_or_update")
        logging.info(f"      resource_group_name={resource_group_name}")
        logging.info(f"      vault_name={key_vault_name}")
        vault = keyvault_client.vaults.begin_create_or_update(
            resource_group_name=resource_group_name,
            vault_name=key_vault_name,
            parameters=key_vault_properties,
        ).result()
        return vault

    def update_key_vault_access_policy(
        self,
        keyvault_client,
        resource_group_name,
        key_vault_name,
        tenant_id,
        app_object_id,
        stg_object_id,
    ):
        access_policy_storage = AccessPolicyEntry(
            tenant_id=tenant_id,
            object_id=stg_object_id,
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
        access_policy = [access_policy_app, access_policy_storage]

        logging.info("Updating Key Vault Access Policy")
        logging.info("executing keyvault_client.vaults.update_access_policy")
        logging.info(f"      resource_group_name={resource_group_name}")
        logging.info(f"      vault_name={key_vault_name}")
        keyvault_client.vaults.update_access_policy(
            resource_group_name=resource_group_name,
            vault_name=key_vault_name,
            operation_kind=AccessPolicyUpdateKind.ADD,
            parameters=VaultAccessPolicyParameters(
                properties=VaultAccessPolicyProperties(access_policies=access_policy),
            ),
        )

    def create_key(self, credential, key_vault_name, suffix):
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
        rsa_key_name = key_vault_name + "-" + suffix
        logging.info("creating a key")
        rsa_key = key_client.create_rsa_key(
            rsa_key_name, size=2048, expires_on=expires_on, enabled=True
        )
        return rsa_key

    def remediate(
        self,
        client_id,
        tenant_id,
        keyvault_client,
        monitor_client,
        storage_client,
        graph_client,
        credentials,
        resource_group_name,
        key_vault_name,
        region,
        subscription_id,
    ):
        """Enable key vault logging
        :param client_id: Azure Client ID.
        :param tenant_id: Azure Tenant ID.
        :param graph_client: Instance of the AzureGraphRbacManagementClient.
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
        try:
            key_vault = keyvault_client.vaults.get(
                resource_group_name=resource_group_name, vault_name=key_vault_name,
            )
            key_vault_id = key_vault.id
            log = LogSettings(
                category="AuditEvent",
                enabled=True,
                retention_policy=RetentionPolicy(enabled=True, days=180),
            )
            app_details = graph_client.applications.get_service_principals_id_by_app_id(
                application_id=client_id
            )
            app_object_id = app_details.value
            # Check if the Storage Account Created by CHSS is available in the same region
            stg_name = generate_name(region, subscription_id, resource_group_name)
            stg_account = self.check_stg_account(
                storage_client, region, stg_name, resource_group_name
            )
            if stg_account is None:
                logging.info("    Creating a Storage Account")
                logging.info(
                    "    executing client_storage.storage_accounts.begin_create"
                )
                logging.info(f"      resource_group_name={resource_group_name}")
                logging.info(f"      account_name={stg_name}")
                stg_account = self.create_storage_account(
                    resource_group_name, stg_name, region, storage_client
                )
                app_details = graph_client.applications.get_service_principals_id_by_app_id(
                    application_id=client_id
                )
                app_object_id = app_details.value

                # Check if the Key Vault created by CHSS exists in that region
                encryption_key_vault_name = generate_name(
                    region, subscription_id, resource_group_name
                )
                key_vault = self.check_key_vault(
                    keyvault_client,
                    region,
                    encryption_key_vault_name,
                    resource_group_name,
                )
                if key_vault is None:
                    # Creating Key Vault and Key to encrypt Storage Account and storing the key vault logs in the storage account.
                    encryption_key_vault = self.create_key_vault(
                        keyvault_client,
                        resource_group_name,
                        encryption_key_vault_name,
                        region,
                        tenant_id,
                        app_object_id,
                        stg_account.identity.principal_id,
                    )
                    key = self.create_key(
                        credentials, encryption_key_vault_name, stg_account.name
                    )
                    self.update_storage_account_encryption(
                        storage_client,
                        resource_group_name,
                        stg_name,
                        key.name,
                        encryption_key_vault.properties.vault_uri,
                    )
                    self.create_diagnostic_setting(
                        monitor_client,
                        encryption_key_vault.id,
                        encryption_key_vault.name,
                        stg_account.id,
                        log,
                    )
                else:
                    # Updating the key vault access policy to give permissions for both app and storage account to encrypt the storage account.
                    self.update_key_vault_access_policy(
                        keyvault_client,
                        resource_group_name,
                        key_vault.name,
                        tenant_id,
                        app_object_id,
                        stg_account.identity.principal_id,
                    )
                    key = self.create_key(credentials, key_vault.name, stg_account.name)
                    self.update_storage_account_encryption(
                        storage_client,
                        resource_group_name,
                        stg_account.name,
                        key.name,
                        key_vault.properties.vault_uri,
                    )

                # Creating Diagnostic settings to store violated Key vault's logs
                self.create_diagnostic_setting(
                    monitor_client, key_vault_id, key_vault_name, stg_account.id, log
                )
            else:
                # Creating Diagnostic settings to store violated Key vault's logs
                self.create_diagnostic_setting(
                    monitor_client, key_vault_id, key_vault_name, stg_account.id, log
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

        # credential for Storage Account and Key Vault management client
        credential = ClientSecretCredential(
            client_id=client_id, client_secret=client_secret, tenant_id=tenant_id,
        )

        # credential for AzureGraphRbacManagementClient
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
            client_id,
            tenant_id,
            keyvault_client,
            monitor_client,
            storage_client,
            graph_client,
            credential,
            params["resource_group_name"],
            params["key_vault_name"],
            params["region"],
            params["subscription_id"],
        )


if __name__ == "__main__":
    sys.exit(EnableKeyVaultLogging().run(sys.argv))
