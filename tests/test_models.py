from unittest import TestCase

from pygitguardian.models import Document


class TestModel(TestCase):
    def test_document_model(self):
        document = Document("hello", "hello")
        self.assertIsInstance(document.to_json(), str)
        self.assertIsInstance(document.to_dict(), dict)
        self.assertIsInstance(str(document), str)
