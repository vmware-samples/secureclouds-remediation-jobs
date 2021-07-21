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

from remediation_worker.jobs.ebs_private_snapshot.ebs_private_snapshot import EBSPrivateSnapshot

@pytest.fixture
def valid_payload():
    return """ {
    "notificationInfo": {
        "FindingInfo": {
            "ObjectId": "i-00347a2be30cf1a15",
            "Region": "us-east-1"
        }
    }
  }
"""


class TestEBSPrivateSnapshot:
    def test_parse_payload(self, valid_payload):
        obj = EBSPrivateSnapshot()
        param = obj.parse(valid_payload)
        assert "snapshot_id" in param
        assert param["snapshot_id"] == "i-00347a2be30cf1a15"
        assert "region" in param
        assert param["region"] == "us-east-1"

    def test_remediate_success(self):
        class TestClient(object):
            def modify_snapshot_attribute(self, **kwargs):
                return 0

            def describe_snapshot_attribute(self, **kwargs):
                return ({
                   "SnapshotId": "snap-066877671789bd71b",
                   "CreateVolumePermissions": [
                    {
                       "UserId": "123456789012",
                       'Group': 'all'
                    }

                    ]
                })

        client = TestClient()
        obj = EBSPrivateSnapshot()
        assert obj.remediate(client, "snap-01a972f6209ba8d24", "us-west-2") == 0

    def test_remediate_not_success(self):
        class TestClient(object):
            def modify_snapshot_attribute(self, **kwargs):
                return 0

            def describe_snapshot_attribute(self, **kwargs):
                return ({})

        client = TestClient()
        obj = EBSPrivateSnapshot()
        assert obj.remediate(client, "snap-01a972f6209ba8d24", "us-west-2") == 1
