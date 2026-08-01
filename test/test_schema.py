import unittest

from audit_analysis.model import ResultatAxe, strict_schema


def objects(schema: dict):
    """Tous les sous-schémas de type object, y compris dans $defs."""
    found = []
    stack = [schema]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("type") == "object":
                found.append(node)
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return found


class StrictSchemaTests(unittest.TestCase):
    """L'API refuse un schéma d'objet sans additionalProperties: false."""

    def setUp(self) -> None:
        self.schema = strict_schema(ResultatAxe)

    def test_every_object_forbids_extra_properties(self) -> None:
        for node in objects(self.schema):
            with self.subTest(node=node.get("title")):
                self.assertIs(node["additionalProperties"], False)

    def test_every_property_is_required(self) -> None:
        """Un champ à valeur par défaut sort de `required` chez Pydantic ;
        la sortie structurée les veut tous."""
        for node in objects(self.schema):
            with self.subTest(node=node.get("title")):
                self.assertEqual(sorted(node["required"]), sorted(node["properties"]))

    def test_keeps_the_schema_usable(self) -> None:
        self.assertIn("constats", self.schema["properties"])
        self.assertIn("$defs", self.schema)

    def test_does_not_mutate_the_pydantic_schema(self) -> None:
        first = ResultatAxe.model_json_schema()
        strict_schema(ResultatAxe)

        self.assertEqual(ResultatAxe.model_json_schema(), first)


if __name__ == "__main__":
    unittest.main()
