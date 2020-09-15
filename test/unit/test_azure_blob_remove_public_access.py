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

from remediation_worker.jobs.azure_blob_remove_public_access.azure_blob_remove_public_access import (
    StorageBlobRemovePublicAccess,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "5c6cc5e103dcc90f363146cd",
        "Service": "Storage",
        "FindingInfo": {
            "FindingId": "d0431afd-b82e-4021-8aa6-ba3cf5c60ef7",
            "ObjectId": "storage_account_name.default.container_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Storage.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.BlobContainer.storage_account_name.default.container_name\\",\\"entityName\\":\\"storage_account_name.default.container_name\\",\\"entityType\\":\\"Azure.Storage.BlobContainer\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Storage\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestBlobRemovePublicAccess(object):
    def test_parse_payload(self, valid_payload):
        params = StorageBlobRemovePublicAccess().parse(valid_payload)
        assert params["account_name"] == "storage_account_name"
        assert params["container_name"] == "container_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = StorageBlobRemovePublicAccess()
        assert (
            action.remediate(client, "resource_group", "account_name", "container_name")
            == 0
        )
        assert client.blob_containers.update.call_count == 1

        call_args = client.blob_containers.update.call_args
        updated_container = call_args[1]["blob_container"]
        assert updated_container.public_access == "None"

    def test_remediate_with_exception(self):
        client = Mock()
        client.blob_containers.update.side_effect = Exception
        action = StorageBlobRemovePublicAccess()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
