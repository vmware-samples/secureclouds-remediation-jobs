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
from botocore.exceptions import ClientError

from remediation_worker.jobs.s3_remove_public_admin_acl.s3_remove_public_admin_acl import (
    S3RemovePublicAdminAcl,
)


@pytest.fixture
def valid_payload1():
    return """
        {
            "notificationInfo": {
                "FindingInfo": {
                    "ObjectId": "foo"
                }
            }
        }
    """


@pytest.fixture
def invalid_payload():
    return """
        {
            "notificationInfo": {
                "FindingInfo": {
                    "None": "foo"
                }
            }
        }
    """


class TestS3RemovePublicAdminAcl(object):
    def test_parse_payload_success(self, valid_payload1):
        obj = S3RemovePublicAdminAcl()
        result = obj.parse(valid_payload1)
        assert "bucket_name" in result

    def test_parse_payload_with_missing_param(self, invalid_payload):
        obj = S3RemovePublicAdminAcl()
        with pytest.raises(Exception):
            assert obj.parse(invalid_payload)

    def test_remediate_success(self):
        class TestClient(object):
            def put_public_access_block(self, **kwargs):
                return None

            def put_bucket_acl(self, **kwargs):
                return None

            def get_bucket_acl(self, **kwargs):
                return {
                    "Owner": {"DisplayName": "someownerid", "ID": "alongid"},
                    "Grants": [
                        {
                            "Grantee": {
                                "DisplayName": "displaynameagain",
                                "ID": "someid",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "FULL_CONTROL",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            },
                            "Permission": "WRITE",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            },
                            "Permission": "READ_ACP",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "Permission": "READ",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "Permission": "WRITE",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "Permission": "READ_ACP",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "Permission": "WRITE_ACP",
                        },
                    ],
                }

        client = TestClient()
        action = S3RemovePublicAdminAcl()
        assert action.remediate(client, "bucket_name") == 0

    def test_remediate_success_full_control(self):
        class TestClient(object):
            def put_public_access_block(self, **kwargs):
                return None

            def put_bucket_acl(self, **kwargs):
                return None

            def get_bucket_acl(self, **kwargs):
                return {
                    "Owner": {"DisplayName": "someownerid", "ID": "alongid"},
                    "Grants": [
                        {
                            "Grantee": {
                                "DisplayName": "displaynameagain",
                                "ID": "someid",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "FULL_CONTROL",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            },
                            "Permission": "WRITE",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            },
                            "Permission": "READ_ACP",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                            },
                            "Permission": "FULL_CONTROL",
                        },
                    ],
                }

        client = TestClient()
        action = S3RemovePublicAdminAcl()
        assert action.remediate(client, "bucket_name") == 0

    def test_remediate_success_no_grants(self):
        class TestClient(object):
            def put_public_access_block(self, **kwargs):
                return None

            def put_bucket_acl(self, **kwargs):
                return None

            def get_bucket_acl(self, **kwargs):
                return {
                    "Owner": {"DisplayName": "someownerid", "ID": "alongid"},
                    "Grants": [
                        {
                            "Grantee": {
                                "DisplayName": "displaynameagain",
                                "ID": "someid",
                                "Type": "CanonicalUser",
                            },
                            "Permission": "FULL_CONTROL",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            },
                            "Permission": "WRITE",
                        },
                        {
                            "Grantee": {
                                "Type": "Group",
                                "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                            },
                            "Permission": "READ_ACP",
                        },
                    ],
                }

        client = TestClient()
        action = S3RemovePublicAdminAcl()
        assert action.remediate(client, "bucket_name") == 0

    def test_remediate_with_exception(self):
        class TestClient(object):
            def put_bucket_encryption(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "NotFound",
                            "Message": "InvalidPermission.NotFound",
                        }
                    },
                    "TestS3RemovePublicAdminAcl",
                )

        client = TestClient()
        action = S3RemovePublicAdminAcl()
        with pytest.raises(Exception):
            assert action.remediate(client, "bucket_name")
