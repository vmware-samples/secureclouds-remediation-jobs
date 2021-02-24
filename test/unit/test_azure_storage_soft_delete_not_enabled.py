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
from azure.mgmt.storage.models import DeleteRetentionPolicy
from remediation_worker.jobs.azure_storage_soft_delete_not_enabled.azure_storage_soft_delete_not_enabled import (
    EnableBlobServiceSoftDelete,
)


@pytest.fixture
def valid_payload():
    return """
{
    "notificationInfo": {
        "RuleId": "99d645b8-aa87-11ea-bb37-0242ac130002",
        "Service": "Storage",
        "FindingInfo": {
            "FindingId": "9b2da5e9-bb96-4298-b2c1-e6c341b44c5f",
            "ObjectId": "storage_account_name",
            "ObjectChain": "{\\"cloudAccountId\\":\\"subscription_id\\",\\"entityId\\":\\"Azure.Storage.d687b1a3-9b78-43b1-a17b-7de297fd1fce.resource_group_name.StorageAccount.testingresourcename\\",\\"entityName\\":\\"testingresourcename\\",\\"entityType\\":\\"Azure.Storage.StorageAccount\\",\\"lastUpdateTime\\":\\"2020-09-09T00:36:35.000Z\\",\\"partitionKey\\":\\"d687b1a3-9b78-43b1-a17b-7de297fd1fce\\",\\"provider\\":\\"Azure\\",\\"region\\":\\"eastus\\",\\"service\\":\\"Storage\\", \\"properties\\":[{\\"name\\":\\"ResourceGroup\\",\\"stringV\\":\\"resource_group_name\\",\\"type\\":\\"string\\"}]}",
            "Region": "region"
            }
        }
}
"""


class TestDefaultActionDeny(object):
    def test_parse_payload(self, valid_payload):
        params = EnableBlobServiceSoftDelete().parse(valid_payload)
        assert params["account_name"] == "storage_account_name"
        assert params["resource_group_name"] == "resource_group_name"
        assert params["subscription_id"] == "subscription_id"
        assert params["region"] == "region"

    def test_remediate_success(self):
        client = Mock()
        action = EnableBlobServiceSoftDelete()
        assert action.remediate(client, "resource_group", "account_name") == 0
        assert client.blob_services.set_service_properties.call_count == 1

        call_args = client.blob_services.set_service_properties.call_args
        updated_blob_service = call_args[1]["parameters"]
        blob_soft_delete = DeleteRetentionPolicy(enabled=True, days=7)
        assert updated_blob_service.delete_retention_policy == blob_soft_delete

    def test_remediate_with_exception(self):
        client = Mock()
        client.blob_services.set_service_properties.side_effect = Exception
        action = EnableBlobServiceSoftDelete()
        with pytest.raises(Exception):
            assert action.remediate(client, "security_group_id", "resource_group")
