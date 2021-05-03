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
from azure.graphrbac import GraphRbacManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import Sku as sku_storage
from azure.mgmt.sql.models import (
    ResourceIdentity,
    IdentityType,
    EncryptionProtector,
    ServerKey,
    Server,
)
from azure.mgmt.storage.models import (
    StorageAccountCreateParameters,
    NetworkRuleSet,
    SkuName,
    SkuTier,
    DefaultAction,
    Identity,
    Encryption,
    KeySource,
    KeyVaultProperties,
    BlobServiceProperties,
    DeleteRetentionPolicy,
    StorageAccountListResult,
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
    AccessPolicyUpdateKind,
    VaultListResult,
    VaultAccessPolicyParameters,
    VaultAccessPolicyProperties,
)

logging.basicConfig(level=logging.INFO)

MAX_COUNT_SUBSCRIPTION = 5
MAX_COUNT_RESOURCE_NAME = 5
MAX_COUNT_REGION = 6
MAX_COUNT_COMPONENT = 4


def generate_name(region, subscription_id, resource_group_name):
    """Generates a name for the resource
    :param region: location in which the resource exists
    :param subscription_id: Azure Subscription Id
    :param resource_group_name: Resource group name in which the resource exists
    :type region: str
    :type subscription_id: str
    :type resource_group_name: str
    :returns: resource name
    :rtype: str
    """
    random_str = "".join(i for i in subscription_id if i.islower() or i.isdigit())
    subscription_id = random_str[:MAX_COUNT_SUBSCRIPTION]
    random_str = "".join(i for i in region if i.islower() or i.isdigit())
    region = random_str[-MAX_COUNT_REGION:]
    random_str = "".join(i for i in resource_group_name if i.islower() or i.isdigit())
    resource_group_name = random_str[-MAX_COUNT_RESOURCE_NAME:]
    result_str = "chss" + subscription_id + resource_group_name + region + "logs"
    return result_str


class SqlServerEncryptTdeProtector(object):
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
        logging.info(f"  sql_server_name: {object_id}")
        logging.info(f"  subscription_id: {subscription_id}")
        logging.info(f"  region: {region}")
        return {
            "resource_group_name": resource_group_name,
            "sql_server_name": object_id,
            "subscription_id": subscription_id,
            "region": region,
        }

    def check_stg_account(self, storage_client, region, name, resource_group_name):
        """Checks For the existence of the Storage Account created by CHSS
        :param storage_client: Instance of the Azure StorageManagementClient.
        :param region: The location in which the storage account exists.
        :param name: The Storage Account name.
        :param resource_group_name: The name of the resource group.
        :type storage_client: object
        :type region: str
        :type name: str
        :type resource_group_name: str
        :returns: StorageAccount object
        :rtype: object
        """
        storage_accounts_paged: ItemPaged[
            StorageAccountListResult
        ] = storage_client.storage_accounts.list()
        storage_accounts_list: List[dict] = list(storage_accounts_paged)
        storage_account = None
        for stg_account in storage_accounts_list:
            stg_id = stg_account.id
            stg_components = stg_id.split("/")
            if len(stg_components) > MAX_COUNT_COMPONENT:
                resource_grp = stg_components[MAX_COUNT_COMPONENT]
                if (
                    stg_account.name == name
                    and stg_account.location == region
                    and resource_grp == resource_group_name
                ):
                    storage_account = stg_account
                    break
        return storage_account

    def check_key_vault(self, keyvault_client, region, name, resource_group_name):
        """Checks for the existence of the Key Vault created by CHSS.
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param region: The location in which the Key Vault exists.
        :param name: Key Vault name.
        :param resource_group_name: The name of the resource group.
        :type keyvault_client: object
        :type region: str
        :type name: str
        :type resource_group_name: str
        :returns: Vault object
        :rtype: object
        """
        key_vault_paged: ItemPaged[
            VaultListResult
        ] = keyvault_client.vaults.list_by_subscription()
        key_vault_list: List[dict] = list(key_vault_paged)
        chss_key_vault = None
        for key_vault in key_vault_list:
            key_vault_id = key_vault.id
            key_vault_components = key_vault_id.split("/")
            if len(key_vault_components) > MAX_COUNT_COMPONENT:
                resource_grp = key_vault_components[MAX_COUNT_COMPONENT]
                if (
                    key_vault.name == name
                    and key_vault.location == region
                    and resource_grp == resource_group_name
                ):
                    chss_key_vault = key_vault
                    break
        return chss_key_vault

    def create_storage_account(
        self, resource_group_name, name, region, storage_client,
    ):
        """Creates a Storage Account
        :param storage_client: Instance of the Azure StorageManagementClient.
        :param region: The location in which the storage account exists.
        :param name: The Storage Account name.
        :param resource_group_name: The name of the resource group.
        :type storage_client: object
        :type region: str
        :type name: str
        :type resource_group_name: str
        :returns: StorageAccount object
        :rtype: object
        """

        create_params = StorageAccountCreateParameters(
            location=region,
            sku=sku_storage(name=SkuName.STANDARD_LRS, tier=SkuTier.STANDARD),
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
        """Updates Storage Account Encryption for a Storage Account.
        :param storage_client: Instance of the Azure StorageManagementClient.
        :param resource_group_name: The name of the resource group.
        :param stg_name: The Storage Account name.
        :param key_name: Name of the Key to encrypt the Storage Account with.
        :param vault_uri: Key Vault uri in which the Key exists.
        :type storage_client: object
        :type resource_group_name: str
        :type stg_name: str
        :type key_name: str
        :type vault_uri: str
        :returns: None
        :rtype: None
        """
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

    def create_diagnostic_setting(
        self, monitor_client, key_vault_id, key_vault_name, stg_account_id, log
    ):
        """Creates a diagnostic setting
        :param monitor_client: Instance of the Azure StorageManagementClient.
        :param key_vault_id: The resource Id of the Key Vault.
        :param key_vault_name: Name of the Key Vault.
        :param stg_account_id: The Storage Account resource Id.
        :param log: Instance of Azure Monitor LogSettings
        :type monitor_client: object
        :type log: object
        :type key_vault_id: str
        :type key_vault_name: str
        :type stg_account_id: str
        :returns: None
        :rtype: None
        """
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
        principal_id,
    ):
        """Creates a Key Vault
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param resource_group_name: The name of the resource group.
        :param key_vault_name: Name of the Key Vault.
        :param region: location of the Key Vault.
        :param tenant_id: Azure tenant Id
        :param app_object_id: Object Id of the application
        :param principal_id: Principal Id of the Resource
        :type keyvault_client: object
        :type resource_group_name: str
        :type key_vault_name: str
        :type region: str
        :type tenant_id: str
        :type app_object_id: str
        :type principal_id: str
        :returns: Vault object
        :rtype: object
        """
        access_policy_storage_account = AccessPolicyEntry(
            tenant_id=tenant_id,
            object_id=principal_id,
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
            permissions=Permissions(keys=[KeyPermissions.GET, KeyPermissions.CREATE]),
        )
        key_vault_properties = VaultCreateOrUpdateParameters(
            location=region,
            tags={"Created By": "CHSS"},
            properties=VaultProperties(
                tenant_id=tenant_id,
                sku=Sku(family="A", name="standard",),
                access_policies=[access_policy_storage_account, access_policy_app],
                soft_delete_retention_in_days=7,
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
        """Updates Key Vault Access Policy
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param resource_group_name: The name of the resource group.
        :param key_vault_name: Name of the Key Vault.
        :param region: The location in which the Key Vault exists.
        :param tenant_id: Azure tenant Id
        :param app_object_id: Object Id of the application
        :param stg_principal_id: Principal Id of the Storage Account
        :type keyvault_client: object
        :type resource_group_name: str
        :type key_vault_name: str
        :type region: str
        :type tenant_id: str
        :type app_object_id: str
        :type stg_principal_id: str
        :returns: None
        :rtype: None
        """
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
            permissions=Permissions(keys=[KeyPermissions.GET, KeyPermissions.CREATE]),
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
        """Creates a Key within the given Key Vault
        :param credential: Azure Credentials
        :param key_vault_name: Name of the Key Vault.
        :param suffix: suffix for Key name
        :type key_vault_name: str
        :type suffix: str
        :returns: Azure Key object which was created
        :rtype: object
        """
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

    def ensure_identity_assigned(
        self, client, resource_group_name, sql_server_name, region
    ):
        """Checks if the Identity is assigned to the SQL Server. If not then it assigns the identity
        :param client: Instance of the Azure SqlManagementClient.
        :param resource_group_name: Resource group name
        :param sql_server_name: SQL Server name
        :param region: location in which the SQL Server exists
        :type client: object
        :type resource_group_name: str
        :type sql_server_name: str
        :type region: str
        :returns: Principal Id of the SQL Server
        :rtype: str
        """
        server = client.servers.get(
            resource_group_name=resource_group_name, server_name=sql_server_name,
        )
        if server.identity is None:
            logging.info(
                f"Assigning Azure Active Directory Identity to the SQL Database Server {sql_server_name}"
            )
            logging.info("executing client.servers.update")
            logging.info(f"      resource_group_name={resource_group_name}")
            logging.info(f"      server_name={sql_server_name}")
            server = client.servers.begin_create_or_update(
                resource_group_name=resource_group_name,
                server_name=sql_server_name,
                parameters=Server(
                    location=region,
                    identity=ResourceIdentity(type=IdentityType.system_assigned),
                ),
            ).result()
        return server.identity.principal_id

    def ensure_key_with_permission_exists(
        self,
        key_vault_name,
        client_id,
        tenant_id,
        credentials,
        client,
        client_storage,
        keyvault_client,
        graph_client,
        monitor_client,
        resource_group_name,
        sql_server_name,
        region,
        subscription_id,
        principal_id,
        app_object_id,
    ):
        """Ensure that a Key Vault with key created by CHSS exists
        :param client_id: Azure Client ID.
        :param tenant_id: Azure Tenant ID.
        :param graph_client: Instance of the AzureGraphRbacManagementClient.
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param monitor_client: Instance of the Azure MonitorClient.
        :param credentials: Azure Credential object.
        :param client: Instance of the Azure SqlManagementClient.
        :param client_storage: Instance of the Azure StorageManagementClient.
        :param resource_group_name: The name of the resource group to which the SQL Server belongs.
        :param sql_server_name: The name of the SQL Server.
        :param subscription_id: Azure Subscription Id
        :param principal_id: SQL Server Principal Id.
        :param app_object_id: Object Id of the Application that is running the code.
        :type client_id: str
        :type tenant_id: str
        :type graph_client: object
        :type keyvault_client: object
        :type client_storage: object
        :type monitor_client: object
        :type credentials: object
        :type client: object
        :type resource_group_name: str.
        :type sql_server_name: str.
        :type region: str.
        :type subscription_id: str
        :type principal_id: str.
        :type app_object_id: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """
        # Check if the Key Vault created by CHSS exists in the given region and resource group.
        key_vault = self.check_key_vault(
            keyvault_client, region, key_vault_name, resource_group_name
        )
        if key_vault is None:
            # If the Key Vault does not exists then create the Key Vault.
            key_vault = self.create_key_vault(
                keyvault_client,
                resource_group_name,
                key_vault_name,
                region,
                tenant_id,
                app_object_id,
                principal_id,
            )
            log = LogSettings(
                category="AuditEvent",
                enabled=True,
                retention_policy=RetentionPolicy(enabled=True, days=180),
            )

            # Check if the Storage Account created by CHSS exists in the given region and resource group.
            stg_name = generate_name(region, subscription_id, resource_group_name)
            stg_account = self.check_stg_account(
                client_storage, region, stg_name, resource_group_name
            )
            if stg_account is None:
                # If the Storage Account does not exists then create the Storage Account.
                stg_account = self.create_storage_account(
                    resource_group_name, stg_name, region, client_storage
                )

                # Create a Key to encrypt the Storage Account.
                key = self.create_key(credentials, key_vault.name, stg_account.name)
                
                # Update the Access policy for the Key Vault to give access to the Storage Account which is being created.
                self.update_key_vault_access_policy(
                    keyvault_client,
                    resource_group_name,
                    key_vault_name,
                    tenant_id,
                    app_object_id,
                    stg_account.identity.principal_id,
                )
                # Encrypt the Storage Account which is being created with the above Key.
                self.update_storage_account_encryption(
                    client_storage,
                    resource_group_name,
                    stg_name,
                    key.name,
                    key_vault.properties.vault_uri,
                )
            # Create Diagnostic Setting to store key vault logs
            self.create_diagnostic_setting(
                monitor_client, key_vault.id, key_vault.name, stg_account.id, log,
            )
        else:
            # If the Key Vault exists then update the access policy to give access to app and the Storage Account
            self.update_key_vault_access_policy(
                keyvault_client,
                resource_group_name,
                key_vault_name,
                tenant_id,
                app_object_id,
                principal_id,
            )
        # Create a Key to encrypt the Sql Server TDE.
        key = self.create_key(credentials, key_vault_name, sql_server_name)
        return key

    def remediate(
        self,
        client_id,
        tenant_id,
        credentials,
        client,
        client_storage,
        keyvault_client,
        graph_client,
        monitor_client,
        resource_group_name,
        sql_server_name,
        region,
        subscription_id,
    ):
        """Enable Server blob auditing policy for Azure SQL Server
        :param client_id: Azure Client ID.
        :param tenant_id: Azure Tenant ID.
        :param graph_client: Instance of the AzureGraphRbacManagementClient.
        :param keyvault_client: Instance of the Azure KeyVaultManagementClient.
        :param monitor_client: Instance of the Azure MonitorClient.
        :param credentials: Azure Credential object.
        :param client: Instance of the Azure SqlManagementClient.
        :param client_storage: Instance of the Azure StorageManagementClient.
        :param resource_group_name: The name of the resource group to which the SQL Server belongs.
        :param sql_server_name: The name of the SQL Server.
        :param subscription_id: Azure Subscription Id
        :type client_id: str
        :type tenant_id: str
        :type graph_client: object
        :type keyvault_client: object
        :type client_storage: object
        :type monitor_client: object
        :type credentials: object
        :type client: object
        :type resource_group_name: str.
        :type sql_server_name: str.
        :type region: str.
        :type subscription_id: str
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """
        try:
            app_details = graph_client.applications.get_service_principals_id_by_app_id(
                application_id=client_id
            )
            # Check if identity is assigned. If not then assign the identity.
            principal_id = self.ensure_identity_assigned(
                client, resource_group_name, sql_server_name, region
            )

            key_vault_name = generate_name(region, subscription_id, resource_group_name)

            # Ensure that a Key Vault with key created by CHSS exists.
            key = self.ensure_key_with_permission_exists(
                key_vault_name,
                client_id,
                tenant_id,
                credentials,
                client,
                client_storage,
                keyvault_client,
                graph_client,
                monitor_client,
                resource_group_name,
                sql_server_name,
                region,
                subscription_id,
                principal_id,
                app_details.value,
            )

            # Create an SQL Server Key
            server_key_name = (
                key_vault_name + "_" + key.name + "_" + key.properties.version
            )
            client.server_keys.begin_create_or_update(
                resource_group_name=resource_group_name,
                server_name=sql_server_name,
                key_name=server_key_name,
                parameters=ServerKey(server_key_type="AzureKeyVault", uri=key.id),
            ).result()

            # Update the SQL TDE protector to encrypt using cmk
            client.encryption_protectors.begin_create_or_update(
                resource_group_name=resource_group_name,
                server_name=sql_server_name,
                encryption_protector_name="current",
                parameters=EncryptionProtector(
                    server_key_name=server_key_name, server_key_type="AzureKeyVault"
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

        # credential for Storage Account and Key Vault management and SQL client
        credential = ClientSecretCredential(
            client_id=client_id, client_secret=client_secret, tenant_id=tenant_id,
        )

        # credential for AzureGraphRbacManagementClient
        credentials_graph = ServicePrincipalCredentials(
            client_id=client_id,
            secret=client_secret,
            tenant=tenant_id,
            resource="https://graph.windows.net",
        )

        client_storage = StorageManagementClient(credential, params["subscription_id"])

        keyvault_client = KeyVaultManagementClient(
            credential, params["subscription_id"]
        )
        graph_client = GraphRbacManagementClient(
            credentials_graph, tenant_id, base_url=None
        )

        monitor_client = MonitorClient(credential, params["subscription_id"])

        client = SqlManagementClient(
            credential, params["subscription_id"], base_url=None
        )
        return self.remediate(
            client_id,
            tenant_id,
            credential,
            client,
            client_storage,
            keyvault_client,
            graph_client,
            monitor_client,
            params["resource_group_name"],
            params["sql_server_name"],
            params["region"],
            params["subscription_id"],
        )


if __name__ == "__main__":
    sys.exit(SqlServerEncryptTdeProtector().run(sys.argv))
