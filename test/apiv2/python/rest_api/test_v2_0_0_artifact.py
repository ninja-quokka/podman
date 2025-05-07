import unittest

import requests
import urllib
from .fixtures import APITestCase


class ArtifactTestCase(APITestCase):
    artifact_name = "quay.io/myimage/myartifact:latest"

    def test_add(self):
        file = "/bin/ls"
        parameters = {
            "name": self.artifact_name,
            "file": "ls",
            # FIX: "annotations": '["test:true", "test1:false"]',
            "type": "application/octet-stream",
        }
        with open(file, "rb") as file_to_upload:
            file_content = file_to_upload.read()
            r = requests.post(
                self.uri("/artifacts/add"), data=file_content, params=parameters
            )

        self.assertEqual(r.status_code, 201, r.text)

        # return looks like:
        # {'ArtifactDigest': 'sha256:65626d4c06f9b83567f924b4839056dd5821b1072ee5ed4bf156db404c564ec4'}
        artifact = r.json()
        self.assertIn("sha256:", artifact["ArtifactDigest"])

    def test_inspect(self):
        # Test inspecting an artifact that exists
        url = self.uri(
            "/artifacts/" + urllib.parse.quote(self.artifact_name, safe="") + "/json"
        )
        r = requests.get(url)

        self.assertEqual(r.status_code, 200, r.text)

        data = r.json()
        expected_top_level = {"Manifest", "Name", "Digest"}
        expected_manifest = {"schemaVersion", "mediaType", "config", "layers"}
        expected_config = {"mediaType", "digest", "size", "data"}
        expected_layer = {"mediaType", "digest", "size", "annotations"}

        missing_top = expected_top_level - data.keys()
        manifest = data.get("Manifest", {})
        missing_manifest = expected_manifest - manifest.keys()
        config = manifest.get("config", {})
        missing_config = expected_config - config.keys()

        layers = manifest.get("layers", [])
        for i, layer in enumerate(layers):
            missing_layer = expected_layer - layer.keys()
            self.assertFalse(missing_layer)

        # assert all missing dicts are empty
        self.assertFalse(missing_top)
        self.assertFalse(missing_manifest)
        self.assertFalse(missing_config)

        # Test inspecting an artifact that doesn't exist
        url = self.uri("/artifacts/" + "fake_artifact" + "/json")
        r = requests.get(url)

        self.assertEqual(r.status_code, 404, r.text)


if __name__ == "__main__":
    unittest.main()
