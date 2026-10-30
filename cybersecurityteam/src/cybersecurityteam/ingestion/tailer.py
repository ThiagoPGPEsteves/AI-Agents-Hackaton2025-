import os
import json
import time
from pathlib import Path
from typing import Generator, Optional

class LogTailer:
    """
    Leitor incremental de arquivos de log em tempo real (estilo 'tail -f').
    Suporta persistência de offset, rotação de arquivos e retenção de linhas parciais.
    """
    def __init__(self, file_path: str, offset_file: Optional[str] = None):
        self.file_path = Path(file_path)
        self.offset_file = Path(offset_file) if offset_file else self.file_path.parent / ".offset.json"
        self.offset_file.parent.mkdir(parents=True, exist_ok=True)
        self.last_offset = self._load_offset()
        self._partial_buffer = ""

    def _load_offset(self) -> int:
        if self.offset_file.exists():
            try:
                with open(self.offset_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("offset", 0)
            except Exception:
                return 0
        return 0

    def _save_offset(self, offset: int):
        self.last_offset = offset
        try:
            with open(self.offset_file, "w", encoding="utf-8") as f:
                json.dump({"offset": offset, "file": str(self.file_path)}, f)
        except Exception:
            pass

    def read_new_lines(self) -> Generator[str, None, None]:
        """Lê novas linhas completas disponíveis no arquivo sem bloquear o loop."""
        if not self.file_path.exists():
            return

        current_size = self.file_path.stat().st_size
        # Detecção de rotação ou truncamento
        if current_size < self.last_offset:
            self.last_offset = 0

        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(self.last_offset)
            chunk = f.read()
            if not chunk:
                return

            full_chunk = self._partial_buffer + chunk
            lines = full_chunk.split("\n")

            # O último elemento após o split pode ser uma linha incompleta
            if not full_chunk.endswith("\n"):
                self._partial_buffer = lines.pop()
            else:
                self._partial_buffer = ""

            for line in lines:
                clean_line = line.strip()
                if clean_line:
                    yield clean_line

            self._save_offset(f.tell())

    def follow(self, poll_interval: float = 0.5) -> Generator[str, None, None]:
        """Loop contínuo de observação de novas linhas."""
        while True:
            yielded = False
            for line in self.read_new_lines():
                yield line
                yielded = True
            if not yielded:
                time.sleep(poll_interval)
