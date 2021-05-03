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
from remediation_worker.jobs.azure_key_vault_is_recoverable.azure_key_vault_is_recoverable import (
    KeyVaultIsRecoverable,
)
from azure.mgmt.keyvault.models import Vault, VaultProperties, Sku


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c268d7a550e1fb6560cc0",
        "Service": "Vault",
        "FindingInfo": {
            "FindingId": "d3bb1d9a-fe52-4458-9935-47183f140e6b",
            "ObjectId": "key_vault_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.KeyVault.Vault.d687b1a3-9b78-43b1-a17b-7de297fd1fce.integration-tests-postgresql-b3wx.Key.postgresqlwnuuobrlrwngs\\",\\"entityName\\":\\"key_vault_name\\",\\"entityType\\":\\"Azure.KeyVault.Vault\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"PostgreSQL\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestSetExpirationForKey(object):
    def test_parse_payload(self, valid_payload):
        params = KeyVaultIsRecoverable().parse(valid_payload)
        assert params["key_vault_name"] == "key_vault_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_soft_delete_true_purge_protection_none(self):
        client = Mock()
        action = KeyVaultIsRecoverable()

        client.vaults.get.return_value = Vault(
            location="westus",
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/resgroup/providers/Microsoft.KeyVault/vaults/clarity1",
            name="clarity1",
            properties=VaultProperties(
                tenant_id="bhH874fgjeKJiphFGH873",
                sku=Sku(family="A", name="standard",),
                enable_soft_delete=True,
                enable_purge_protection=None,
            ),
        )

        assert action.remediate(client, "resource_group_name", "key_vault_name") == 0
        assert client.vaults.update.call_count == 1
        call_args = client.vaults.update.call_args
        updated_parameters = call_args[1]["parameters"]
        assert updated_parameters.properties.enable_purge_protection is True
        assert client.vaults.get.call_count == 1

    def test_remediate_soft_delete_none(self):
        client = Mock()
        action = KeyVaultIsRecoverable()

        client.vaults.get.return_value = Vault(
            location="westus",
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/resgroup/providers/Microsoft.KeyVault/vaults/clarity1",
            name="clarity1",
            properties=VaultProperties(
                tenant_id="bhH874fgjeKJiphFGH873",
                sku=Sku(family="A", name="standard",),
                enable_soft_delete=None,
                enable_purge_protection=None,
            ),
        )

        assert action.remediate(client, "resource_group_name", "key_vault_name") == 0
        assert client.vaults.update.call_count == 1
        call_args = client.vaults.update.call_args
        updated_parameters = call_args[1]["parameters"]
        assert updated_parameters.properties.enable_soft_delete is True
        assert updated_parameters.properties.enable_purge_protection is True
        assert client.vaults.get.call_count == 1

    def test_remediate_with_exception(self):
        client = Mock()
        client.client.vaults.update.side_effect = Exception
        action = KeyVaultIsRecoverable()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
