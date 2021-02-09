import json
import os
import sys
import logging
import uuid
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
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql.models import (
    ServerBlobAuditingPolicy,
    BlobAuditingPolicyState,
    ResourceIdentity,
    IdentityType,
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
from azure.mgmt.authorization.models import (
    RoleAssignmentCreateParameters,
    RoleAssignmentListResult,
    RoleAssignmentProperties,
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


class SqlServerEnableBlobAuditingPolicy(object):
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

    def check_role_assignment(
        self, client_authorization, scope, principal_id, role_definition_id
    ):
        role_assignment_paged: ItemPaged[
            RoleAssignmentListResult
        ] = client_authorization.role_assignments.list_for_scope(scope=scope)
        role_assignment_list: List[dict] = list(role_assignment_paged)
        number_of_ddos: int = len(role_assignment_list)
        print(number_of_ddos)
        for role in role_assignment_list:
            if (
                role.principal_id == principal_id
                and role.role_definition_id == role_definition_id
            ):
                return True
        return False

    def create_storage_account(self, resource_group_name, name, region, storage_client):
        from azure.mgmt.storage.models import Sku

        create_params = StorageAccountCreateParameters(
            location=region,
            sku=Sku(name=SkuName.STANDARD_LRS, tier=SkuTier.STANDARD),
            identity=Identity(type="SystemAssigned"),
            kind="StorageV2",
            enable_https_traffic_only=True,
            network_rule_set=NetworkRuleSet(default_action=DefaultAction.DENY),
            tags={"CreatedBy": "CHSS"},
        )
        logging.info("    Creating a Storage Account")
        logging.info("    executing client_storage.storage_accounts.begin_create")
        logging.info(f"      resource_group_name={resource_group_name}")
        logging.info(f"      account_name={name}")
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
        logging.info("          creating a key")
        logging.info(f"         vault_url=https://{key_vault_name}.vault.azure.net/")
        rsa_key = key_client.create_rsa_key(
            rsa_key_name, size=2048, expires_on=expires_on, enabled=True
        )
        return rsa_key

    def create_role_assignment(
        self,
        stg_account_name,
        subscription_id,
        client_authorization,
        guid,
        Scope,
        principalId,
        sql_server_name,
    ):
        logging.info(
            f"Creating a Role Assignment for Storage Account {stg_account_name} and assigning Storage Blob Data Contributer Role to the SQL Database Server {sql_server_name}"
        )
        logging.info("executing client_authorization.role_assignments.create")
        logging.info(f"      scope={Scope}")
        logging.info(f"      role_assignment_name={guid}")
        client_authorization.role_assignments.create(
            scope=Scope,
            role_assignment_name=guid,
            parameters=RoleAssignmentCreateParameters(
                properties=RoleAssignmentProperties(
                    role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe",
                    principal_id=principalId,
                ),
            ),
        )

    def create_server_blob_auditing_policy(
        self, resource_group_name, sql_server_name, stg_account_name, client
    ):
        logging.info("Enabling Server blob auditing policy for Azure SQL Server")
        logging.info(
            "    executing client.server_blob_auditing_policies.create_or_update"
        )
        logging.info(f"      resource_group_name={resource_group_name}")
        logging.info(f"      server_name={sql_server_name}")

        client.server_blob_auditing_policies.create_or_update(
            resource_group_name=resource_group_name,
            server_name=sql_server_name,
            parameters=ServerBlobAuditingPolicy(
                state=BlobAuditingPolicyState.enabled,
                storage_endpoint=f"https://{stg_account_name}.blob.core.windows.net/",
            ),
        )

    def ensure_identity_assigned(
        self, client, resource_group_name, sql_server_name, region
    ):
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
            updated_server = client.servers.update(
                resource_group_name=resource_group_name,
                server_name=sql_server_name,
                parameters=Server(
                    location=region,
                    identity=ResourceIdentity(type=IdentityType.system_assigned),
                ),
            ).result()
            return updated_server.identity.principal_id
        else:
            return server.identity.principal_id

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
        client_authorization,
        resource_group_name,
        sql_server_name,
        region,
        subscription_id,
    ):
        """Enable Server blob auditing policy for Azure SQL Server
        :param client: Instance of the Azure SqlManagementClient.
        :param client_storage: Instance of the Azure StorageManagementClient.
        :param resource_group_name: The name of the resource group to which the SQL Server belongs.
        :param sql_server_name: The name of the SQL Server.
        :type resource_group_name: str.
        :type sql_server_name: str.
        :type region: str.
        :returns: Integer signaling success or failure
        :rtype: int
        :raises: msrestazure.azure_exceptions.CloudError
        """
        try:
            guid = uuid.uuid4()
            principalId = self.ensure_identity_assigned(
                client, resource_group_name, sql_server_name, region
            )

            stg_name = generate_name(region, subscription_id, resource_group_name)
            stg_account = self.check_stg_account(
                client_storage, region, stg_name, resource_group_name
            )
            if stg_account is None:
                stg_account = self.create_storage_account(
                    resource_group_name, stg_name, region, client_storage,
                )

                app_details = graph_client.applications.get_service_principals_id_by_app_id(
                    application_id=client_id
                )
                app_object_id = app_details.value

                log = LogSettings(
                    category="AuditEvent",
                    enabled=True,
                    retention_policy=RetentionPolicy(enabled=True, days=180),
                )
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
                        client_storage,
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
                    self.update_key_vault_access_policy(
                        keyvault_client,
                        resource_group_name,
                        key_vault.name,
                        tenant_id,
                        app_object_id,
                        stg_account.identity.principal_id,
                    )
                    key = self.create_key(credentials, key_vault.name, stg_account.name)
                    key_vault_uri = key_vault.properties.vault_uri
                    self.update_storage_account_encryption(
                        client_storage,
                        resource_group_name,
                        stg_account.name,
                        key.name,
                        key_vault_uri,
                    )

                Scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Storage/storageAccounts/{stg_account.name}"
                self.create_role_assignment(
                    stg_name,
                    subscription_id,
                    client_authorization,
                    guid,
                    Scope,
                    principalId,
                    sql_server_name,
                )
                self.create_server_blob_auditing_policy(
                    resource_group_name, sql_server_name, stg_name, client
                )
            else:
                stg_id = stg_account.id
                stg_components = stg_id.split("/")
                resource_grp = stg_components[4]
                Scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_grp}/providers/Microsoft.Storage/storageAccounts/{stg_account.name}"
                role_definition_id = f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/ba92f5b4-2d11-453d-a403-e96b0029c9fe"
                status = self.check_role_assignment(
                    client_authorization, Scope, principalId, role_definition_id
                )
                if status:
                    self.create_server_blob_auditing_policy(
                        resource_group_name, sql_server_name, stg_account.name, client
                    )
                else:
                    self.create_role_assignment(
                        stg_account.name,
                        subscription_id,
                        client_authorization,
                        guid,
                        Scope,
                        principalId,
                        sql_server_name,
                    )
                    self.create_server_blob_auditing_policy(
                        resource_group_name, sql_server_name, stg_account.name, client
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
        credentials_graph = ServicePrincipalCredentials(
            client_id=client_id,
            secret=client_secret,
            tenant=tenant_id,
            resource="https://graph.windows.net",
        )

        # credential for SqlManagementClient and
        credentials = ServicePrincipalCredentials(
            client_id=client_id, secret=client_secret, tenant=tenant_id,
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
            credentials, params["subscription_id"], base_url=None
        )

        client_authorization = AuthorizationManagementClient(
            credential, params["subscription_id"], api_version="2018-01-01-preview"
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
            client_authorization,
            params["resource_group_name"],
            params["sql_server_name"],
            params["region"],
            params["subscription_id"],
        )


if __name__ == "__main__":
    sys.exit(SqlServerEnableBlobAuditingPolicy().run(sys.argv))
