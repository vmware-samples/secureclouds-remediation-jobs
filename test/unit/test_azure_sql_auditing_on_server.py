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

import pytest
from mock import Mock
from remediation_worker.jobs.azure_sql_auditing_on_server.azure_sql_auditing_on_server import (
    SqlServerEnableBlobAuditingPolicy,
)
from azure.mgmt.storage.models import (
    StorageAccount,
    Identity,
)
from azure.mgmt.keyvault.models import (
    VaultProperties,
    Vault,
    Sku,
)
from azure.keyvault.keys import KeyVaultKey


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c268a7a550e1fb6560cb9",
        "Service": "Microsoft.Sql",
        "FindingInfo": {
            "FindingId": "d3bb1d9a-fe52-4458-9935-47183f140e6b",
            "ObjectId": "sql_server_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Microsoft.Sql.server.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.Microsoft.Sql.server.testingresourcename\\",\\"entityName\\":\\"testingresourcename\\",\\"entityType\\":\\"Azure.Microsoft.Sql.server\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Storage\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestSqlServerAuditing(object):
    def test_parse_payload(self, valid_payload):
        params = SqlServerEnableBlobAuditingPolicy().parse(valid_payload)
        assert params["sql_server_name"] == "sql_server_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_without_stg_without_keyvault(self):
        client = Mock()
        client_authorization = Mock()
        client_storage = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        graph_client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()

        action = SqlServerEnableBlobAuditingPolicy()
        action.create_key = Mock()
        action.create_key_vault = Mock()
        action.check_key_vault = Mock()
        action.check_stg_account = Mock()
        action.update_storage_account_encryption = Mock()
        action.create_diagnostic_setting = Mock()
        action.create_storage_account = Mock()
        action.ensure_identity_assigned = Mock()
        action.create_role_assignment = Mock()
        action.create_server_blob_auditing_policy = Mock()

        identity = Identity(
            principal_id="139bcf82-e14e-4773-bcf4-1da136674792",
            type="SystemAssigned",
            tenant_id="b39138ca-3cee-4b4a-a4d6-cd83d9dd62f0",
        )
        action.ensure_identity_assigned.return_value = (
            "139bcf82-e14e-4773-bcf4-1da136674792"
        )
        action.create_key_vault.return_value = Vault(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/kshrutika-1/providers/Microsoft.KeyVault/vaults/stg-keyvault-rem",
            name="stg-keyvault-rem",
            properties=VaultProperties(
                tenant_id=tenant_id,
                sku=Sku(family="A", name="standard"),
                vault_uri="https://stg-keyvault-rem.vault.azure.net",
            ),
        )
        action.create_key.return_value = KeyVaultKey(
            key_id="https://stg-keyvault-rem.vault.azure.net/keys/rem-key1/0d7a89bd1f8447b4b65ce962212476b0",
            name="rem-key1",
        )
        action.create_storage_account.return_value = StorageAccount(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Sql/servers/remserver5",
            name="remstg5",
            type="Microsoft.Storage/storageAccounts",
            location="eastus",
            identity=identity,
        )
        action.check_stg_account.return_value = None
        action.check_key_vault.return_value = None
        assert (
            action.remediate(
                client_id,
                tenant_id,
                credentials,
                client,
                client_storage,
                keyvault_client,
                graph_client,
                monitor_client,
                client_authorization,
                "resource_group_name",
                "sql_server_name",
                "region",
                "subscription_id",
            )
            == 0
        )
        assert action.ensure_identity_assigned.call_count == 1
        assert action.check_key_vault.call_count == 1
        assert action.check_stg_account.call_count == 1
        assert action.create_key.call_count == 1
        assert action.update_storage_account_encryption.call_count == 1
        assert action.create_storage_account.call_count == 1
        assert action.create_key_vault.call_count == 1
        assert action.create_diagnostic_setting.call_count == 1
        assert action.create_role_assignment.call_count == 1
        assert action.create_server_blob_auditing_policy.call_count == 1

    def test_remediate_without_stg_with_keyvault(self):
        client = Mock()
        client_authorization = Mock()
        client_storage = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        graph_client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()

        action = SqlServerEnableBlobAuditingPolicy()
        action.create_key = Mock()
        action.check_key_vault = Mock()
        action.check_stg_account = Mock()
        action.update_key_vault_access_policy = Mock()
        action.update_storage_account_encryption = Mock()
        action.create_diagnostic_setting = Mock()
        action.create_storage_account = Mock()
        action.ensure_identity_assigned = Mock()
        action.create_role_assignment = Mock()
        action.create_server_blob_auditing_policy = Mock()

        identity = Identity(
            principal_id="139bcf82-e14e-4773-bcf4-1da136674792",
            type="SystemAssigned",
            tenant_id="b39138ca-3cee-4b4a-a4d6-cd83d9dd62f0",
        )
        action.ensure_identity_assigned.return_value = (
            "139bcf82-e14e-4773-bcf4-1da136674792"
        )
        action.create_key.return_value = KeyVaultKey(
            key_id="https://stg-keyvault-rem.vault.azure.net/keys/rem-key1/0d7a89bd1f8447b4b65ce962212476b0",
            name="rem-key1",
        )
        action.create_storage_account.return_value = StorageAccount(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Sql/servers/remserver5",
            name="remstg5",
            type="Microsoft.Storage/storageAccounts",
            location="eastus",
            identity=identity,
        )
        action.check_stg_account.return_value = None
        action.check_key_vault.return_value = Vault(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/kshrutika-1/providers/Microsoft.KeyVault/vaults/stg-keyvault-rem",
            name="stg-keyvault-rem",
            properties=VaultProperties(
                tenant_id=tenant_id,
                sku=Sku(family="A", name="standard"),
                vault_uri="https://stg-keyvault-rem.vault.azure.net",
            ),
        )
        assert (
            action.remediate(
                client_id,
                tenant_id,
                credentials,
                client,
                client_storage,
                keyvault_client,
                graph_client,
                monitor_client,
                client_authorization,
                "resource_group_name",
                "sql_server_name",
                "region",
                "subscription_id",
            )
            == 0
        )
        assert action.ensure_identity_assigned.call_count == 1
        assert action.check_key_vault.call_count == 1
        assert action.check_stg_account.call_count == 1
        assert action.create_key.call_count == 1
        assert action.update_key_vault_access_policy.call_count == 1
        assert action.update_storage_account_encryption.call_count == 1
        assert action.create_storage_account.call_count == 1
        assert action.create_role_assignment.call_count == 1
        assert action.create_server_blob_auditing_policy.call_count == 1

    def test_remediate_with_exception(self):
        client = Mock()
        client_authorization = Mock()
        client_storage = Mock()
        client_id = Mock()
        client.server_blob_auditing_policies.create_or_update.side_effect = Exception
        action = SqlServerEnableBlobAuditingPolicy()
        with pytest.raises(Exception):
            assert action.remediate(
                client_id,
                client,
                client_storage,
                client_authorization,
                "resource_group_name",
                "sql_server_name",
            )
