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
from remediation_worker.jobs.azure_key_vault_expiry_date_set_for_all_secrets.azure_key_vault_expiry_date_set_for_all_secrets import (
    SetExpirationForSecret,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c268d7a550e1fb6560cc0",
        "Service": "Secret",
        "FindingInfo": {
            "FindingId": "d3bb1d9a-fe52-4458-9935-47183f140e6b",
            "ObjectId": "key_vault_name.secret_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.KeyVault.Secret.d687b1a3-9b78-43b1-a17b-7de297fd1fce.integration-tests-postgresql-b3wx.Key.postgresqlwnuuobrlrwngs\\",\\"entityName\\":\\"key_vault_name.key_name\\",\\"entityType\\":\\"Azure.KeyVault.Secret\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"PostgreSQL\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestSetExpirationForKey(object):
    def test_parse_payload(self, valid_payload):
        params = SetExpirationForSecret().parse(valid_payload)
        assert params["key_vault_name"] == "key_vault_name"
        assert params["secret_name"] == "secret_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_rbac_enabled_no_role_assignment(self):
        secret_client = Mock()
        client_authorization = Mock()
        keyvault_client = Mock()
        graph_client = Mock()
        client_id = Mock()
        tenant_id = Mock()
        action = SetExpirationForSecret()
        action.check_rbac_enabled = Mock()
        action.check_role_assignment = Mock()
        action.create_role_assignment = Mock()
        action.ensure_secret_permissions = Mock()

        action.check_rbac_enabled.return_value = True
        action.check_role_assignment.return_value = False

        assert (
            action.remediate(
                tenant_id,
                client_id,
                secret_client,
                keyvault_client,
                graph_client,
                client_authorization,
                "resource_group_name",
                "key_vault_name",
                "secret_name",
                "subscription_id",
            )
            == 0
        )
        assert secret_client.update_secret_properties.call_count == 1
        assert action.ensure_secret_permissions.call_count == 1

    def test_remediate_rbac_enabled_with_role_assignment(self):
        secret_client = Mock()
        client_authorization = Mock()
        keyvault_client = Mock()
        graph_client = Mock()
        client_id = Mock()
        tenant_id = Mock()
        action = SetExpirationForSecret()
        action.check_rbac_enabled = Mock()
        action.check_role_assignment = Mock()
        action.create_role_assignment = Mock()
        action.ensure_secret_permissions = Mock()

        action.check_rbac_enabled.return_value = True
        action.check_role_assignment.return_value = True

        assert (
            action.remediate(
                tenant_id,
                client_id,
                secret_client,
                keyvault_client,
                graph_client,
                client_authorization,
                "resource_group_name",
                "key_vault_name",
                "secret_name",
                "subscription_id",
            )
            == 0
        )
        assert secret_client.update_secret_properties.call_count == 1
        assert action.ensure_secret_permissions.call_count == 1

    def test_remediate_no_rbac_enabled(self):
        secret_client = Mock()
        client_authorization = Mock()
        keyvault_client = Mock()
        graph_client = Mock()
        client_id = Mock()
        tenant_id = Mock()
        action = SetExpirationForSecret()
        action.check_rbac_enabled = Mock()
        action.ensure_secret_permissions = Mock()
        action.update_key_vault_access_policy = Mock()

        action.check_rbac_enabled.return_value = False

        assert (
            action.remediate(
                tenant_id,
                client_id,
                secret_client,
                keyvault_client,
                graph_client,
                client_authorization,
                "resource_group_name",
                "key_vault_name",
                "secret_name",
                "subscription_id",
            )
            == 0
        )
        assert secret_client.update_secret_properties.call_count == 1
        assert action.ensure_secret_permissions.call_count == 1

    def test_remediate_with_exception(self):
        secret_client = Mock()
        secret_client.update_secret_properties.side_effect = Exception
        action = SetExpirationForSecret()
        with pytest.raises(Exception):
            assert action.remediate(
                secret_client, "security_group_id", "resource_group"
            )
