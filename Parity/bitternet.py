import os
import shutil
import tempfile
import psutil
import json
import time
import secrets

class BitterNet:
    def __init__(self):
        self.defaultBlocks = os.path.abspath("../Blocks")
        if os.path.islink(self.defaultBlocks) or os.path.realpath(self.defaultBlocks) != self.defaultBlocks:
            raise RuntimeError("Unsafe Blocks directory.")
        self.accessibleDisks = self.get_drives()
        self.locBlocks()

    def get_drives(self):
        try:
            return [d.device for d in psutil.disk_partitions()]
        except Exception as e:
            print(f"FailureToReadDisks: {e}")
            return []

    def generateBlockDirectories(self):
        family_tree_path = self._secure_join(self.defaultBlocks, "familytree.json")
        if os.path.islink(family_tree_path):
            raise RuntimeError("Symlink detected for familytree.json.")
        tmp_path = family_tree_path + ".tmp"
        if os.path.isfile(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        # TODO: Implement concurrency/file locks if multiple processes might write simultaneously
        if os.path.isfile(family_tree_path):
            try:
                with open(family_tree_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if not isinstance(data, dict):
                    data = {}
            except (json.JSONDecodeError, OSError):
                data = {}
        else:
            data = {}

        # TODO: Encrypt or sign data at rest for additional security
        if "encryption_heartbeat" not in data:
            data["encryption_heartbeat"] = secrets.token_hex(16)
        if "initialized_at" not in data:
            data["initialized_at"] = int(time.time())

        data["disks"] = []
        for i, disk in enumerate(self.accessibleDisks):
            data["disks"].append({
                "parent": disk,
                "heartbeat": i,
                "disk_label": f"disk-{i}",
            })

        self._write_secure_json(family_tree_path, data)

    def _write_secure_json(self, file_path, data):
        # TODO: Add OS-specific ACL checks or mandatory access control
        if not os.path.isdir(os.path.dirname(file_path)) or os.path.islink(os.path.dirname(file_path)):
            raise RuntimeError("Invalid directory for data.")

        fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(file_path))
        os.close(fd)
        try:
            with open(temp_path, "w", encoding="utf-8") as tmp_file:
                json.dump(data, tmp_file, indent=4)
            try:
                os.chmod(temp_path, 0o600)
            except OSError:
                pass
            shutil.move(temp_path, file_path)
        except:
            try:
                os.remove(temp_path)
            except OSError:
                pass
            raise

    def locBlocks(self):
        try:
            if not os.path.isdir(self.defaultBlocks):
                os.makedirs(self.defaultBlocks, exist_ok=True)
            if os.path.islink(self.defaultBlocks):
                raise RuntimeError("Symlink detected in blocks directory.")

            # TODO: Further checks on blocks directory structure or disk presence
            dlist = os.listdir(self.defaultBlocks)
            if len(dlist) == len(self.accessibleDisks):
                print("Disks Exist")
            else:
                self.generateBlockDirectories()
        except Exception as e:
            print(f"ErrorToInitBlocks: {e}")

    def _secure_join(self, base, *paths):
        final_path = os.path.join(base, *paths)
        cp = os.path.commonpath([os.path.abspath(base), os.path.abspath(final_path)])
        if cp != os.path.abspath(base):
            raise RuntimeError("Attempted directory traversal.")
        return final_path

if __name__ == "__main__":
    BitterNet()
