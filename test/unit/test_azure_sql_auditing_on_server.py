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
from azure.mgmt.sql.models import Server, ResourceIdentity, BlobAuditingPolicyState


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c8c268a7a550e1fb6560cb9",
        "Service": "Sql",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "sql_server_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Sql.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.Server.sql_server_name\\",\\"entityName\\":\\"sql_server_name\\",\\"entityType\\":\\"Azure.Sql.Server\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Sql\\",\\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestEnableDdosProtection(object):
    def test_parse_payload(self, valid_payload):
        params = SqlServerEnableBlobAuditingPolicy().parse(valid_payload)
        assert params["sql_server_name"] == "sql_server_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success_without_server_identity(self):
        client = Mock()
        client_stg = Mock()
        client_auth = Mock()
        client.servers.get.return_value = Server(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Sql/servers/remserver5",
            name="remserver5",
            type="Microsoft.Sql/servers",
            location="eastus",
            identity=None,
            administrator_login="accelerators",
            administrator_login_password=None,
            state="Ready",
            fully_qualified_domain_name="remserver5.database.windows.net",
            public_network_access="Enabled",
        )
        resource_identity = ResourceIdentity(
            principal_id="139bcf82-e14e-4773-bcf4-1da136674792",
            type="SystemAssigned",
            tenant_id="b39138ca-3cee-4b4a-a4d6-cd83d9dd62f0",
        )
        client.servers.update.result.return_value = Server(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Sql/servers/remserver5",
            name="remserver5",
            type="Microsoft.Sql/servers",
            location="eastus",
            identity=resource_identity,
            administrator_login="accelerators",
            administrator_login_password=None,
            state="Ready",
            fully_qualified_domain_name="remserver5.database.windows.net",
            public_network_access="Enabled",
        )

        action = SqlServerEnableBlobAuditingPolicy()
        assert (
            action.remediate(
                client,
                client_stg,
                client_auth,
                "resource_group",
                "sql_server_name",
                "subscription_id",
                "region",
            )
            == 0
        )
        assert client.server_blob_auditing_policies.create_or_update.call_count == 1
        call_args = client.server_blob_auditing_policies.create_or_update.call_args
        updated_auditing_policy = call_args[1]["parameters"]
        assert updated_auditing_policy.state == BlobAuditingPolicyState.enabled

    def test_remediate_success_with_server_identity(self):
        client = Mock()
        client_stg = Mock()
        client_auth = Mock()
        resource_identity = ResourceIdentity(
            principal_id="139bcf82-e14e-4773-bcf4-1da136674792",
            type="SystemAssigned",
            tenant_id="b39138ca-3cee-4b4a-a4d6-cd83d9dd62f0",
        )
        client.servers.get.return_value = Server(
            id="/subscriptions/d687b1a3-9b78-43b1-a17b-7de297fd1fce/resourceGroups/accelerators-team-resources/providers/Microsoft.Sql/servers/remserver5",
            name="remserver5",
            type="Microsoft.Sql/servers",
            location="eastus",
            identity=resource_identity,
            administrator_login="accelerators",
            administrator_login_password=None,
            state="Ready",
            fully_qualified_domain_name="remserver5.database.windows.net",
            public_network_access="Enabled",
        )
        action = SqlServerEnableBlobAuditingPolicy()
        assert (
            action.remediate(
                client,
                client_stg,
                client_auth,
                "resource_group",
                "sql_server_name",
                "subscription_id",
                "region",
            )
            == 0
        )
        assert client.server_blob_auditing_policies.create_or_update.call_count == 1
        call_args = client.server_blob_auditing_policies.create_or_update.call_args
        updated_auditing_policy = call_args[1]["parameters"]
        assert updated_auditing_policy.state == BlobAuditingPolicyState.enabled

    def test_remediate_with_exception(self):
        client = Mock()
        client.virtual_networks.begin_create_or_update.side_effect = Exception
        action = SqlServerEnableBlobAuditingPolicy()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
