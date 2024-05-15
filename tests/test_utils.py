import unittest

from argo_scg.utils import namespace4tenant

namespaces = {
    "default": ["default"],
    "tenant1": ["TENANT1", "TENANT2"],
    "tenant3": ["TENANT3"],
    "tenant4": ["TENANT4"]
}


class Namespace4TenantTests(unittest.TestCase):
    def test_namespace4tenant(self):
        self.assertEqual(namespace4tenant("TENANT1", namespaces), "tenant1")
        self.assertEqual(namespace4tenant("TENANT2", namespaces), "tenant1")
        self.assertEqual(namespace4tenant("TENANT3", namespaces), "tenant3")
        self.assertEqual(namespace4tenant("TENANT4", namespaces), "tenant4")
