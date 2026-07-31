import unittest

from audit_analysis import reduction


def segments_payload(indices: int, shards: int, segments: int) -> dict:
    """Shape of GET /_segments, sized to order."""
    return {
        "indices": {
            f"idx-{i:03d}": {
                "shards": {
                    str(s): [
                        {
                            "routing": {"state": "STARTED", "primary": s == 0, "node": "n1"},
                            "num_committed_segments": segments,
                            "segments": {
                                f"_{g}": {
                                    "generation": g,
                                    "num_docs": 1000 + g,
                                    "deleted_docs": g,
                                    "size_in_bytes": 5_000_000 + g,
                                    "committed": True,
                                    "search": True,
                                    "version": "9.12.0",
                                    "compound": False,
                                }
                                for g in range(segments)
                            },
                        }
                    ]
                    for s in range(shards)
                }
            }
            for i in range(indices)
        }
    }


class SegmentAggregationTests(unittest.TestCase):
    def test_keeps_the_figures_the_prompt_asks_for(self) -> None:
        """The command prompt asks for segment count and size per shard."""
        summary = reduction.summarise_segments(segments_payload(1, 1, 4))

        shard = summary["indices"]["idx-000"]["shards"]["0"][0]
        self.assertEqual(shard["segment_count"], 4)
        self.assertEqual(shard["size_in_bytes_total"], 4 * 5_000_000 + 6)
        self.assertIn("size_in_bytes_max", shard)
        self.assertEqual(shard["deleted_docs_total"], 0 + 1 + 2 + 3)

    def test_drops_the_per_segment_enumeration(self) -> None:
        summary = reduction.summarise_segments(segments_payload(1, 1, 4))

        self.assertNotIn("segments", summary["indices"]["idx-000"]["shards"]["0"][0])

    def test_collapses_a_large_payload_by_at_least_an_order_of_magnitude(self) -> None:
        payload = segments_payload(indices=40, shards=4, segments=25)

        self.assertLess(
            reduction.encoded_size(reduction.summarise_segments(payload)),
            reduction.encoded_size(payload) / 10,
        )


MAPPING = {
    "idx-a": {
        "mappings": {
            "dynamic": True,
            "properties": {
                "message": {"type": "text"},
                "host": {"type": "keyword"},
                "count": {"type": "long"},
                "payload": {"type": "nested", "properties": {"k": {"type": "text"}}},
            },
        }
    }
}


class MappingAggregationTests(unittest.TestCase):
    def test_reports_field_count_and_type_histogram(self) -> None:
        summary = reduction.summarise_mappings(MAPPING)["idx-a"]

        self.assertEqual(summary["field_count"], 5)  # 4 top-level + 1 nested leaf
        self.assertEqual(summary["types"]["text"], 2)
        self.assertEqual(summary["types"]["keyword"], 1)

    def test_flags_dynamic_mapping_and_costly_types(self) -> None:
        summary = reduction.summarise_mappings(MAPPING)["idx-a"]

        self.assertTrue(summary["dynamic"])
        self.assertIn("payload", summary["costly_fields"])

    def test_reports_text_fields_without_a_keyword_subfield(self) -> None:
        summary = reduction.summarise_mappings(MAPPING)["idx-a"]

        self.assertIn("message", summary["text_without_keyword"])


class ClusterStateAggregationTests(unittest.TestCase):
    PAYLOAD = {
        "cluster_name": "c",
        "master_node": "n1",
        "blocks": {"indices": {"idx-a": {"5": {"description": "read-only"}}}},
        "metadata": {
            "indices": {
                "idx-a": {"state": "open", "mappings": {"properties": {"f": {"type": "text"}}}},
                "idx-b": {"state": "open", "mappings": {"properties": {"g": {"type": "text"}}}},
            }
        },
        "routing_table": {
            "indices": {
                "idx-a": {
                    "shards": {
                        "0": [
                            {"state": "STARTED", "primary": True, "node": "n1"},
                            {
                                "state": "UNASSIGNED",
                                "primary": False,
                                "node": None,
                                "unassigned_info": {"reason": "NODE_LEFT"},
                            },
                        ]
                    }
                }
            }
        },
    }

    def test_keeps_unassigned_shards_and_their_reason(self) -> None:
        summary = reduction.summarise_cluster_state(self.PAYLOAD)

        self.assertEqual(summary["unassigned"][0]["index"], "idx-a")
        self.assertEqual(summary["unassigned"][0]["reason"], "NODE_LEFT")

    def test_keeps_blocks_and_master(self) -> None:
        summary = reduction.summarise_cluster_state(self.PAYLOAD)

        self.assertEqual(summary["master_node"], "n1")
        self.assertIn("idx-a", summary["blocks"]["indices"])

    def test_drops_the_mappings_that_indices_mappings_already_carries(self) -> None:
        summary = reduction.summarise_cluster_state(self.PAYLOAD)

        self.assertNotIn("mappings", summary["metadata_indices"]["idx-a"])
        self.assertEqual(summary["metadata_indices"]["idx-a"]["state"], "open")


class BudgetTests(unittest.TestCase):
    """Aggregation is applied only as far as needed, heaviest artefact first."""

    def test_leaves_everything_alone_when_the_axis_already_fits(self) -> None:
        artefacts = {"indices_segments": segments_payload(2, 2, 3)}

        reduced, applied = reduction.fit_to_budget(artefacts, budget_tokens=1_000_000)

        self.assertEqual(applied, [])
        self.assertEqual(reduced, artefacts)

    def test_aggregates_when_the_axis_overflows(self) -> None:
        artefacts = {"indices_segments": segments_payload(40, 4, 25)}

        reduced, applied = reduction.fit_to_budget(artefacts, budget_tokens=1_000)

        self.assertIn("indices_segments", applied)
        self.assertLess(
            reduction.encoded_size(reduced["indices_segments"]),
            reduction.encoded_size(artefacts["indices_segments"]),
        )

    def test_reports_every_aggregation_it_applied(self) -> None:
        artefacts = {
            "indices_segments": segments_payload(20, 4, 25),
            "indices_mappings": MAPPING,
        }

        _, applied = reduction.fit_to_budget(artefacts, budget_tokens=10)

        self.assertEqual(sorted(applied), ["indices_mappings", "indices_segments"])


if __name__ == "__main__":
    unittest.main()
