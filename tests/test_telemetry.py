
import json
import unittest
from copy import deepcopy
from pathlib import Path

from sentinel_casework.telemetry import (
    TelemetryError,
    create_imported_case,
    load_sysmon_file,
    normalize_sysmon_event,
    parse_sysmon_text,
)


ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "telemetry_samples" / "sysmon_demo.json"


class TelemetryTests(unittest.TestCase):

    def setUp(self):
        self.records = json.loads(
            SAMPLE.read_text(encoding="utf-8")
        )

    def test_loads_three_supported_events(self):
        events = load_sysmon_file(SAMPLE)

        self.assertEqual(len(events), 3)

        self.assertEqual(
            [event["action"] for event in events],
            [
                "process_created",
                "network_connection",
                "file_created",
            ],
        )

    def test_normalized_fields_are_compatible(self):
        event = normalize_sysmon_event(
            self.records[0]
        )

        expected = {
            "id",
            "timestamp",
            "source",
            "action",
            "outcome",
            "user",
            "details",
        }

        self.assertTrue(expected <= event.keys())
        self.assertEqual(event["source"], "sysmon")
        self.assertEqual(event["outcome"], "observed")
        self.assertTrue(event["timestamp"].endswith("Z"))

    def test_preserves_original_record(self):
        event = normalize_sysmon_event(
            self.records[0]
        )

        self.assertEqual(
            event["details"]["raw_event"],
            self.records[0],
        )

    def test_network_fields_are_preserved(self):
        event = normalize_sysmon_event(
            self.records[1]
        )

        details = event["details"]

        self.assertEqual(
            details["destination_ip"],
            "198.51.100.25",
        )
        self.assertEqual(
            details["destination_port"],
            "443",
        )

    def test_file_target_is_preserved(self):
        event = normalize_sysmon_event(
            self.records[2]
        )

        self.assertTrue(
            event["details"]["target_filename"].endswith(
                "process-list.txt"
            )
        )

    def test_jsonl_ingestion(self):
        content = "\n".join(
            json.dumps(record)
            for record in self.records
        )

        events = parse_sysmon_text(
            content,
            filename="events.jsonl",
        )

        self.assertEqual(len(events), 3)

    def test_duplicate_source_records_get_unique_ids(self):
        records = [
            deepcopy(self.records[0]),
            deepcopy(self.records[0]),
        ]

        events = parse_sysmon_text(
            json.dumps(records)
        )

        self.assertNotEqual(
            events[0]["id"],
            events[1]["id"],
        )

    def test_rejects_unsupported_event_type(self):
        record = deepcopy(self.records[0])
        record["EventID"] = 99

        with self.assertRaisesRegex(
            TelemetryError,
            "Unsupported Sysmon EventID",
        ):
            normalize_sysmon_event(record)

    def test_rejects_invalid_timestamp(self):
        record = deepcopy(self.records[0])
        record["EventData"]["UtcTime"] = "invalid"

        with self.assertRaises(TelemetryError):
            normalize_sysmon_event(record)

    def test_rejects_missing_network_destination(self):
        record = deepcopy(self.records[1])
        del record["EventData"]["DestinationIp"]

        with self.assertRaises(TelemetryError):
            normalize_sysmon_event(record)

    def test_rejects_malformed_json(self):
        with self.assertRaises(TelemetryError):
            parse_sysmon_text(
                "{invalid",
                filename="events.json",
            )

    def test_rejects_oversized_input(self):
        content = " " * (5 * 1024 * 1024 + 1)

        with self.assertRaisesRegex(
            TelemetryError,
            "exceeds 5 MB",
        ):
            parse_sysmon_text(content)

    def test_rejects_unsupported_extension(self):
        with self.assertRaises(TelemetryError):
            parse_sysmon_text(
                "[]",
                filename="events.evtx",
            )

    def test_creates_imported_case(self):
        events = load_sysmon_file(SAMPLE)

        case = create_imported_case(
            events,
            case_id="IMPORT-001",
        )

        self.assertEqual(
            case["case_id"],
            "IMPORT-001",
        )
        self.assertEqual(
            case["label"],
            "unlabeled",
        )
        self.assertEqual(
            len(case["events"]),
            3,
        )

    def test_rejects_empty_case(self):
        with self.assertRaises(TelemetryError):
            create_imported_case([])
    
    def test_sysmon_utc_timestamp_without_offset(self):
        record = deepcopy(self.records[0])
        record["EventData"]["UtcTime"] = "2026-10-20 10:00:00.123"

        event = normalize_sysmon_event(record)

        self.assertEqual(
            event["timestamp"],
            "2026-10-20T10:00:00.123000Z",
        )

if __name__ == "__main__":
    unittest.main()