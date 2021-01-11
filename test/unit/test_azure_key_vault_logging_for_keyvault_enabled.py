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

    def test_remediate_success(self):
        storage_client = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        action = EnableKeyVaultLogging()
        assert (
            action.remediate(
                keyvault_client,
                monitor_client,
                storage_client,
                "resource_group",
                "key_vault_name",
                "region",
            )
            == 0
        )
        assert storage_client.storage_accounts.begin_create.call_count == 1
        assert monitor_client.diagnostic_settings.create_or_update.call_count == 1

    def test_remediate_with_exception(self):
        client = Mock()
        client.storage_accounts.update.side_effect = Exception
        action = EnableKeyVaultLogging()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
