import json
import os
import shutil
import uuid
from datetime import datetime


#Upravljanje folderom karantina

class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        self.index_file = os.path.join(self.quarantine_dir, "index.json")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self._ensure_index()
    
    def _ensure_index(self):
        if not os.path.exists(self.index_file):
            with open(self.index_file, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)
    
    def _load_index(self):
        with open(self.index_file, "r", encoding="utf-8") as f:
            return json.load(f)
    
    def _save_index(self, data):
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    
    def quarantine_file(self, file_path, malware_name):
        if not os.path.exists(file_path):
            return {"status" : "error", "message": "File not found"}
        
        item_id = str(uuid.uuid4())
        original_name = os.path.basename(file_path)
        quarantined_name = f"{item_id}_{original_name}"
        quarantined_path = os.path.join(self.quarantine_dir, quarantined_name)
        shutil.move(file_path, quarantined_path)

        record = {
            "id": item_id,
            "original_path": file_path,
            "quarantined_path": quarantined_path,
            "malware_name": malware_name,
            "quarantine_time": datetime.utcnow().isoformat()
        }

        data = self._load_index()

        data.append(record)
        self._save_index(data)

        return {"status": "ok", "message": "File moved to quarantine", "item": record}

    def list_items(self):
        return self._load_index()
    
    def restore_file(self, item_id, restore_path=None):
        data = self._load_index()
        item = next((x for x in data if x["id"] == item_id), None)

        if item is None:
            return {"status": "error", "message": "Item not found"}

        source = item["quarantined_path"]
        target = restore_path if restore_path else item["original_path"]

        target_dir = os.path.dirname(target)
        if target_dir:
            os.makedirs(target_dir, exist_ok=True)
        shutil.move(source, target)

        data = [x for x in data if x["id"] != item_id]
        self._save_index(data)

        return {"status": "ok", "message": "File restored", "restored_to": target}