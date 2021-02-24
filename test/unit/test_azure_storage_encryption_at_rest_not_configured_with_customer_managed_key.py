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
from remediation_worker.jobs.azure_storage_encryption_at_rest_not_configured_with_customer_managed_key.azure_storage_encryption_at_rest_not_configured_with_customer_managed_key import (
    StorageAccountNotEncryptedWithCmk,
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
        "RuleId": "99d645b8-aa87-11ea-bb37-0242ac130002",
        "Service": "Storage",
        "FindingInfo": {
            "FindingId": "9b2da5e9-bb96-4298-b2c1-e6c341b44c5f",
            "ObjectId": "account-name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Storage.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.StorageAccount.testingresourcename\\",\\"entityName\\":\\"testingresourcename\\",\\"entityType\\":\\"Azure.Storage.StorageAccount\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Storage\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestestEncryptStorageAccountWithCMK(object):
    def test_parse_payload(self, valid_payload):
        params = StorageAccountNotEncryptedWithCmk().parse(valid_payload)
        assert params["resource_group_name"] == "resource_group_name"
        assert params["account_name"] == "account-name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_with_keyvault(self):
        graph_client = Mock()
        storage_client = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()

        action = StorageAccountNotEncryptedWithCmk()
        action.create_key = Mock()
        action.check_key_vault = Mock()
        action.update_key_vault_access_policy = Mock()
        action.update_storage_account_encryption = Mock()
        action.ensure_identity_assigned = Mock()
        action.create_key.return_value = KeyVaultKey(
            key_id="https://stg-keyvault-rem.vault.azure.net/keys/rem-key1/0d7a89bd1f8447b4b65ce962212476b0",
            name="rem-key1",
        )
        action.ensure_identity_assigned.return_value = (
            "139bcf82-e14e-4773-bcf4-1da136674792"
        )
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
                monitor_client,
                graph_client,
                storage_client,
                keyvault_client,
                client_id,
                tenant_id,
                credentials,
                "resource_group_name",
                "account-name",
                "region",
                "subscription_id",
            )
            == 0
        )
        assert action.ensure_identity_assigned.call_count == 1
        assert action.check_key_vault.call_count == 1
        assert action.create_key.call_count == 1
        assert action.update_key_vault_access_policy.call_count == 1
        assert action.update_storage_account_encryption.call_count == 1

    def test_remediate_without_keyvault_with_stg(self):
        graph_client = Mock()
        storage_client = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()

        action = StorageAccountNotEncryptedWithCmk()
        action.create_key = Mock()
        action.create_key_vault = Mock()
        action.check_key_vault = Mock()
        action.check_stg_account = Mock()
        action.update_storage_account_encryption = Mock()
        action.create_diagnostic_setting = Mock()
        action.ensure_identity_assigned = Mock()

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
        action.check_stg_account.return_value = StorageAccount(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Sql/servers/remserver5",
            name="remstg5",
            type="Microsoft.Storage/storageAccounts",
            location="eastus",
            identity=identity,
        )
        action.check_key_vault.return_value = None
        assert (
            action.remediate(
                monitor_client,
                graph_client,
                storage_client,
                keyvault_client,
                client_id,
                tenant_id,
                credentials,
                "resource_group_name",
                "account-name",
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
        assert action.create_diagnostic_setting.call_count == 1

    def test_remediate_without_keyvault_without_stg(self):
        graph_client = Mock()
        storage_client = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()

        action = StorageAccountNotEncryptedWithCmk()
        action.create_key = Mock()
        action.create_key_vault = Mock()
        action.check_key_vault = Mock()
        action.check_stg_account = Mock()
        action.update_key_vault_access_policy = Mock()
        action.update_storage_account_encryption = Mock()
        action.create_diagnostic_setting = Mock()
        action.create_storage_account = Mock()
        action.ensure_identity_assigned = Mock()

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
                monitor_client,
                graph_client,
                storage_client,
                keyvault_client,
                client_id,
                tenant_id,
                credentials,
                "resource_group_name",
                "account-name",
                "region",
                "subscription_id",
            )
            == 0
        )
        assert action.ensure_identity_assigned.call_count == 1
        assert action.check_key_vault.call_count == 1
        assert action.check_stg_account.call_count == 1
        assert action.create_key.call_count == 2
        assert action.update_key_vault_access_policy.call_count == 1
        assert action.update_storage_account_encryption.call_count == 2
        assert action.create_storage_account.call_count == 1
        assert action.create_diagnostic_setting.call_count == 1

    def test_remediate_with_exception(self):
        graph_client = Mock()
        storage_client = Mock()
        keyvault_client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()
        storage_client.storage_accounts.update.side_effect = Exception
        action = StorageAccountNotEncryptedWithCmk()
        with pytest.raises(Exception):
            assert action.remediate(
                graph_client,
                storage_client,
                keyvault_client,
                client_id,
                tenant_id,
                credentials,
                "resource_group",
                "security_group",
                "region",
            )
