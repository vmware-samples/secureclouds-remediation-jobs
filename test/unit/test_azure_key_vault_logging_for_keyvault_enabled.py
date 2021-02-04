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
from remediation_worker.jobs.azure_key_vault_logging_for_keyvault_enabled.azure_key_vault_logging_for_keyvault_enabled import (
    EnableKeyVaultLogging,
)
from azure.mgmt.storage.models import StorageAccount
from azure.mgmt.keyvault.models import (
    VaultProperties,
    Vault,
    Sku,
)
from azure.keyvault.keys import KeyVaultKey
from azure.mgmt.monitor.models import (
    LogSettings,
    RetentionPolicy,
    DiagnosticSettingsResource,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c26687a550e1fb6560c72",
        "Service": "KeyVault",
        "FindingInfo": {
            "FindingId": "9b2da5e9-bb96-4298-b2c1-e6c341b44c5f",
            "ObjectId": "key_vault_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.KeyVault.d687b1a3-9b78-43b1-a17b-7de297fd1fce.accelerators-team-resources.Vault.key_vault_name\\",\\"entityName\\":\\"key_vault_name\\",\\"entityType\\":\\"Azure.KeyVault.Vault\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"KeyVault\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestKeyVaultLoggingEnabled(object):
    def test_parse_payload(self, valid_payload):
        params = EnableKeyVaultLogging().parse(valid_payload)
        assert params["key_vault_name"] == "key_vault_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success_with_stg_account_available(self):
        client_id = Mock()
        tenant_id = Mock()
        storage_client = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        graph_client = Mock()
        credentials = Mock()
        log = LogSettings(
            category="AuditEvent",
            enabled=True,
            retention_policy=RetentionPolicy(enabled=True, days=180),
        )
        action = EnableKeyVaultLogging()
        action.check_vss_stg_account = Mock()
        action.create_diagnostic_setting = Mock()
        action.check_vss_stg_account.return_value = StorageAccount(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/kshrutika-1/providers/Microsoft.Storage/storageAccounts/chss538f633keyvaultlogs",
            name="chss538f633keyvaultlogs",
            location="eastus",
        )
        action.create_diagnostic_setting.return_value = DiagnosticSettingsResource(
            storage_account_id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/kshrutika-1/providers/Microsoft.Storage/storageAccounts/chss538f633keyvaultlogs",
            logs=[log],
        )
        assert (
            action.remediate(
                client_id,
                tenant_id,
                keyvault_client,
                monitor_client,
                storage_client,
                graph_client,
                credentials,
                "resource_group",
                "key_vault_name",
                "region",
            )
            == 0
        )
        assert action.create_diagnostic_setting.call_count == 1

    def test_remediate_success_without_stg_account_available(self):
        client_id = Mock()
        tenant_id = Mock()
        storage_client = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        graph_client = Mock()
        credentials = Mock()
        action = EnableKeyVaultLogging()
        action.check_vss_stg_account = Mock()
        action.create_key = Mock()
        action.create_key_vault = Mock()
        action.create_diagnostic_setting = Mock()
        action.create_storage_account = Mock()
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
        action.check_vss_stg_account.return_value = None
        assert (
            action.remediate(
                client_id,
                tenant_id,
                keyvault_client,
                monitor_client,
                storage_client,
                graph_client,
                credentials,
                "resource_group",
                "key_vault_name",
                "region",
            )
            == 0
        )
        assert action.create_diagnostic_setting.call_count == 2
        assert action.create_storage_account.call_count == 1
        assert action.create_key_vault.call_count == 1
        assert action.create_key.call_count == 1

    def test_remediate_with_exception(self):
        client_id = Mock()
        tenant_id = Mock()
        storage_client = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        graph_client = Mock()
        credentials = Mock()
        monitor_client.diagnostic_settings.create_or_update.side_effect = Exception
        action = EnableKeyVaultLogging()
        with pytest.raises(Exception):
            assert action.remediate(
                client_id,
                tenant_id,
                keyvault_client,
                monitor_client,
                storage_client,
                graph_client,
                credentials,
                "resource_group",
                "key_vault_name",
                "region",
            )
