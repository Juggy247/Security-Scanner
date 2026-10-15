import gzip
from typing import Tuple

import gridfs
from bson import ObjectId
from pymongo.errors import DuplicateKeyError
from pymongo import MongoClient
from datetime import datetime
from typing import Optional, List, Dict, Any


class PageRecordStore:
    def __init__(self, connection_string: str = "mongodb://localhost:27017/"):
        self.client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
        self.db = self.client["security_scanner"]   # database
        self.collection = self.db["page_records"]   # collection 

    def insert_record(self, record: Dict[str, Any]) -> str:
        result = self.collection.insert_one(record) #asks MongoDB to insert a document.
        # MongoDB automatically generates an _id if you haven't supplied one.
        return str(result.inserted_id) # result.inserted_id - take the ID of the document that MongoDB inserted

    def find_by_url(self, url: str) -> Optional[Dict[str, Any]]:
        # MongoDB looks for a matching document and returns it as a Python dictionary.
        # return None if we dont find one
        return self.collection.find_one({"url": url})

    def find_by_label(self, label: str, limit: int = 50, split: Optional[str] = None) -> List[Dict[str, Any]]:
        query = {"label.value": label}
        if split in {"train", "validation", "test"}:
            query["split"] = split
        return list(self.collection.find(query).limit(limit))

    def find_ready_for_embedding(self, limit: int = 100) -> List[Dict[str, Any]]:
        return list(
            self.collection.find(
                {
                    "processing.status": "ready",
                    "content.text": {"$exists": True, "$ne": None},
                    "content.text_hash": {"$exists": True},
                }
            ).limit(limit)
        )

    def ensure_indexes(self) -> None:

        self.collection.create_index("url", unique=True, name="uniq_url")
        # Partial: failed/rejected-empty records store None and must not collide.
        self.collection.create_index(
            "content.text_hash",
            unique=True,
            name="uniq_text_hash",
            partialFilterExpression={"content.text_hash": {"$type": "string"}},
        )
        self.collection.create_index(
            [("label.value", 1), ("processing.status", 1), ("split", 1)],
            name="label_status_split",
        )

    def insert_record_checked(self, record: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        """Return (outcome, id): outcome is 'inserted', 'duplicate' or 'label_conflict'. Never overwrites."""
        try:
            result = self.collection.insert_one(record)
            return "inserted", str(result.inserted_id)
        except DuplicateKeyError as exc:
            pattern = (exc.details or {}).get("keyPattern") or {}
            by_hash = "content.text_hash" in pattern or "text_hash" in str(exc)
            if by_hash:
                existing = self.collection.find_one(
                    {"content.text_hash": record["content"]["text_hash"]}, {"label.value": 1}
                )
            else:
                existing = self.collection.find_one({"url": record["url"]}, {"label.value": 1})

            if existing is None:
                return "duplicate", None
            if existing.get("label", {}).get("value") != record["label"]["value"]:
                return "label_conflict", str(existing["_id"])
            return "duplicate", str(existing["_id"])

    def save_raw_html(self, raw: bytes, filename: str) -> str:
        fs = gridfs.GridFS(self.db)
        file_id = fs.put(gzip.compress(raw), filename=filename, compression="gzip")
        return str(file_id)

    def load_raw_html(self, file_id: str) -> bytes:
        fs = gridfs.GridFS(self.db)
        return gzip.decompress(fs.get(ObjectId(file_id)).read())

    def set_raw_html_ref(self, record_id: str, file_id: str) -> None:
        self.collection.update_one(
            {"_id": ObjectId(record_id)},
            {"$set": {"content.raw_html_ref": file_id}},
        )

    def delete_failed_by_url(self, url: str) -> int:
        result = self.collection.delete_one({"url": url, "processing.status": "failed"})
        return result.deleted_count

    def find_references(
        self,
        label: str,
        split: str,
        language: str = "en",
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Ready pages of one class in one split, in a stable order. limit=None means no cap."""
        query = {
            "label.value": label,
            "processing.status": "ready",
            "split": split,
            "content.language": language,
        }
        projection = {"content.text": 1, "content.text_hash": 1, "domain": 1}
        cursor = self.collection.find(query, projection).sort("content.text_hash", 1)
        if limit:
            cursor = cursor.limit(limit)
        return list(cursor)

    def find_examples(
        self,
        split: str,
        language: str = "en",
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Ready pages of both classes in one split, as flat dicts, in a stable order. limit=None means no cap."""
        query = {
            "label.value": {"$in": ["phishing", "benign"]},
            "processing.status": "ready",
            "split": split,
            "content.language": language,
        }
        projection = {
            "content.text": 1,
            "content.text_hash": 1,
            "content.word_count": 1,
            "label.value": 1,
            "domain": 1,
        }
        cursor = self.collection.find(query, projection).sort("content.text_hash", 1)
        if limit:
            cursor = cursor.limit(limit)

        examples = []
        for doc in cursor:
            content = doc.get("content", {})
            text = content.get("text")
            if not text:
                continue
            examples.append(
                {
                    "text": text,
                    "label": doc["label"]["value"],
                    "text_hash": content.get("text_hash"),
                    "word_count": content.get("word_count", 0),
                    "domain": doc.get("domain"),
                }
            )
        return examples

    def close(self):
        self.client.close()

"""
Notes: $exists checks whether a field exists in a MongoDB document.
        True means the field must exist.
        False means the field must not exist.

       $ne stands for not equal.
       the field's value must not be None
"""