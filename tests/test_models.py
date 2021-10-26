from typing import OrderedDict

from pygitguardian.models import Document, DocumentSchema, Match, MatchSchema


class TestModel:
    def test_document_model(self):
        """
        GIVEN a simple document
        THEN base model methods should produce the appropriate types.
        """
        document = Document("hello", "hello")
        assert isinstance(document.to_json(), str)
        assert isinstance(document.to_dict(), dict)
        assert isinstance(str(document), str)

    def test_schema_excludes(self):
        """
        GIVEN a simple document and an extra field in dict format
        WHEN loading using the schema
        THEN the extra field should be excluded
        """
        document = {"filename": "hello", "document": "hello", "extra": "field"}
        schema = DocumentSchema()

        document_obj = schema.load(document)
        assert isinstance(document_obj, OrderedDict)

    def test_schema_loads(self):
        """
        GIVEN a simple match and an extra field in dict format
        WHEN loading using the schema
        THEN the extra field should be excluded and the result should be a Match
        """
        match = {"match": "hello", "type": "hello", "extra": "field"}
        schema = MatchSchema()

        match_obj = schema.load(match)
        assert isinstance(match_obj, Match)
