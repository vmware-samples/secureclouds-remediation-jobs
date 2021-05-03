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
from remediation_worker.jobs.azure_sql_tde_protector_encrypted_cmk.azure_sql_tde_protector_encrypted_cmk import (
    SqlServerEncryptTdeProtector,
)

from azure.keyvault.keys import KeyVaultKey, KeyProperties


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


class TestestEncryptSqlTdeWithCMK(object):
    def test_parse_payload(self, valid_payload):
        params = SqlServerEncryptTdeProtector().parse(valid_payload)
        assert params["sql_server_name"] == "sql_server_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        graph_client = Mock()
        client_storage = Mock()
        keyvault_client = Mock()
        monitor_client = Mock()
        client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()

        action = SqlServerEncryptTdeProtector()
        action.ensure_key_with_permission_exists = Mock()

        action.ensure_key_with_permission_exists.return_value = KeyVaultKey(
            key_id="https://stg-keyvault-rem.vault.azure.net/keys/rem-key1/0d7a89bd1f8447b4b65ce962212476b0",
            name="rem-key1",
            properties=KeyProperties(
                key_id="https://stg-keyvault-rem.vault.azure.net/keys/rem-key1/0d7a89bd1f8447b4b65ce962212476b0",
                name="rem-key1",
                version="e28ndjky736dh3y89nstdgqj378",
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
                "resource_group_name",
                "sql_server_name",
                "region",
                "subscription_id",
            )
            == 0
        )
        assert action.ensure_key_with_permission_exists.call_count == 1
        assert client.server_keys.begin_create_or_update.call_count == 1
        assert client.encryption_protectors.begin_create_or_update.call_count == 1

    def test_remediate_with_exception(self):
        graph_client = Mock()
        client_storage = Mock()
        keyvault_client = Mock()
        credentials = Mock()
        client_id = Mock()
        tenant_id = Mock()
        client = Mock()
        client.server_keys.begin_create_or_update.side_effect = Exception
        action = SqlServerEncryptTdeProtector()
        with pytest.raises(Exception):
            assert (
                action.remediate(
                    graph_client,
                    client_storage,
                    keyvault_client,
                    client_id,
                    tenant_id,
                    credentials,
                    "resource_group",
                    "security_group",
                    "region",
                )
                == 0
            )
