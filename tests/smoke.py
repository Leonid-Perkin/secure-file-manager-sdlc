import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import zipfile

project = Path(__file__).resolve().parents[1]
dll = project / "bin/Debug/net10.0/SecureFileManager.dll"
assert dll.exists(), "Сначала выполните dotnet build"

with tempfile.TemporaryDirectory(prefix="sfm-test-") as temp:
    env = {**os.environ, "SFM_DATA_DIR": temp}

    def run(commands, expected_code=0):
        result = subprocess.run(
            ["dotnet", str(dll)], input="\n".join(commands) + "\n",
            text=True, capture_output=True, env=env, timeout=60
        )
        assert result.returncode == expected_code, (result.returncode, result.stdout, result.stderr)
        return result.stdout + result.stderr

    output = run([
        "admin", "admin-password-123",
        "register", "student", "student-password-123",
        "login", "student", "student-password-123",
        "mkdir", "docs",
        "write", "docs/a.json", '{"ok":true}', ".end",
        "write", "docs/a.json", '{"ok":true}', ".end",
        "write", "docs/a.json", "{", ".end",
        "write", "docs/a.xml", "<root><value>1</value></root>", ".end",
        "read", "docs/a.xml",
        "save-note", "docs/note.json", "Заголовок JSON", "Текст JSON",
        "read-note", "docs/note.json",
        "save-note", "docs/note.xml", "Заголовок XML", "Текст XML",
        "read-note", "docs/note.xml",
        "write", "docs/invalid.json", "{", ".end",
        "write", "docs/invalid.xml", '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', ".end",
        "write", "../escape.txt", "read", "../escape.txt",
        "zip", "docs", "data.zip",
        "unzip", "data.zip", "out",
        "read", "out/a.json",
        "users",
        "logout", "login", "admin", "admin-password-123",
        "block", "student", "logout",
        "login", "student", "student-password-123",
        "login", "admin", "admin-password-123",
        "unblock", "student", "exit"
    ])
    assert '{"ok":true}' in output
    assert "Некорректный JSON" in output and "Некорректный или недопустимый XML" in output
    assert "<root><value>1</value></root>" in output
    assert "Заголовок: Заголовок JSON" in output and "Текст: Текст JSON" in output
    assert "Заголовок: Заголовок XML" in output and "Текст: Текст XML" in output
    assert "Путь вне личного каталога" in output
    assert "заблокирована" in output
    assert "Требуются права администратора" in output
    root = Path(temp) / "files/2"
    assert not (root / "docs/invalid.json").exists()
    assert not (root / "docs/invalid.xml").exists()
    assert (root / "out/a.json").read_text().strip() == '{"ok":true}'
    assert (root / "docs/a.xml").read_text().strip() == "<root><value>1</value></root>"
    assert not (Path(temp) / "escape.txt").exists()
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT blocked FROM users WHERE username='student'").fetchone() == (0,)
        assert con.execute("SELECT count(*) FROM operations WHERE success=0").fetchone()[0] >= 3
        assert con.execute("SELECT count(*) FROM operations WHERE action IN ('block','unblock') AND success=1").fetchone()[0] == 2
        assert con.execute("SELECT count(*) FROM files WHERE path='out/a.json'").fetchone()[0] == 1
        assert con.execute("SELECT count(*) FROM operations WHERE action IN ('create','modify') AND target='docs/a.json' AND success=1").fetchone()[0] == 2
        assert con.execute("SELECT count(*) FROM operations WHERE action='admin_access_denied' AND success=0").fetchone()[0] == 1

    with zipfile.ZipFile(root / "evil.zip", "w") as archive:
        archive.writestr("../escaped.txt", "evil")
    output = run(["login", "student", "student-password-123", "unzip", "evil.zip", "bad", "exit"])
    assert "Выход из каталога" in output
    assert not (root / "bad").exists()
    assert not (root / "escaped.txt").exists()

    (root / "note-malicious.xml").write_text('<!DOCTYPE Note [<!ENTITY e SYSTEM "file:///etc/passwd">]><Note><Title>&e;</Title><Text>x</Text></Note>')
    output = run(["login", "student", "student-password-123", "read-note", "note-malicious.xml", "exit"])
    assert "Ошибка:" in output and "root:x:" not in output
    (root / "note-unknown.json").write_text('{"Title":"test","Text":"test","extra":1}')
    output = run(["login", "student", "student-password-123", "read-note", "note-unknown.json", "exit"])
    assert "Ошибка:" in output

    (root / "link").symlink_to(Path(temp), target_is_directory=True)
    output = run(["login", "student", "student-password-123", "read", "link/data.sqlite", "exit"])
    assert "Символические ссылки запрещены" in output

    output = run(["login", "student", "student-password-123", "delete", "docs/a.json", "exit"])
    assert "Файл удалён." in output and not (root / "docs/a.json").exists()
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT deleted FROM files WHERE path='docs/a.json'").fetchone() == (1,)
        assert con.execute("SELECT count(*) FROM operations WHERE action='delete' AND success=1").fetchone()[0] == 1

    output = run(["login", "student' OR 1=1 --", "student-password-123", "exit"])
    assert "Неверный логин" in output
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT count(*) FROM users").fetchone() == (2,)

    output = run(["login", "student", "student-password-123", "read"])
    assert "Ввод завершён" in output
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT status FROM command_attempts WHERE command='read' ORDER BY id DESC LIMIT 1").fetchone() == ("error",)

    proc = subprocess.Popen(["dotnet", str(dll)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env, bufsize=0)
    try:
        buffer = bytearray()
        while b"\xd0\xb3\xd0\xbe\xd1\x81\xd1\x82\xd1\x8c> " not in buffer:
            chunk = proc.stdout.read(1)
            assert chunk, "Приложение завершилось до приглашения"
            buffer.extend(chunk)
        assert "Работа остановлена:" in run(["exit"], expected_code=1)
        proc.stdin.write(b"login\n")
        proc.stdin.flush()
        buffer.clear()
        while b"\xd0\x9b\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd: " not in buffer:
            chunk = proc.stdout.read(1)
            assert chunk, "Приложение завершилось до ввода логина"
            buffer.extend(chunk)
        proc.kill()
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT status FROM command_attempts WHERE command='login' ORDER BY id DESC LIMIT 1").fetchone() == ("started",)
    output = run(["login", "admin", "admin-password-123", "audit", "exit"])
    assert "Попытки команд" in output and "| login | started" in output
    output = run(["login", "admin", "admin-password-123", "audit 2", "exit"])
    assert "Попытки команд (до 2;" in output and output.count("UTC |") == 4

    output = run(["read", "register", "other", "other-password-123",
                  "login", "other", "other-password-123",
                  "read", "../2/out/a.json", "exit"])
    assert "Необходим вход" in output and "Путь вне личного каталога" in output
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT count(*) FROM operations WHERE action='access_denied'").fetchone()[0] >= 1

    with zipfile.ZipFile(root / "many.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for i in range(1001):
            archive.writestr(f"{i}.txt", "")
    output = run(["login", "student", "student-password-123", "unzip", "many.zip", "many", "exit"])
    assert "Более 1000 элементов" in output
    assert not (root / "many").exists()

    with zipfile.ZipFile(root / "large.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        with archive.open("large.txt", "w") as entry:
            for _ in range(101):
                entry.write(b"\0" * (1024 * 1024))
    output = run(["login", "student", "student-password-123", "unzip", "large.zip", "large", "exit"])
    assert "Лимит распаковки: 100 МиБ" in output
    assert not (root / "large").exists()

    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        con.execute("""
            CREATE TRIGGER test_fault BEFORE INSERT ON files
            WHEN NEW.path='recovery.txt'
            BEGIN SELECT RAISE(ABORT,'test fault'); END
        """)
    output = run(["login", "student", "student-password-123",
                  "write", "recovery.txt", "recovered data", ".end"], expected_code=1)
    assert "перезапустите приложение" in output
    assert (root / "recovery.txt").read_text() == "recovered data\n"
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT action,path FROM file_intents").fetchall() == [("create", "recovery.txt")]
        assert con.execute("SELECT count(*) FROM files WHERE path='recovery.txt'").fetchone() == (0,)
        con.execute("DROP TRIGGER test_fault")
    output = run(["exit"])
    assert "метаданные операции create сверены с диском" in output
    assert "Восстановление:" not in run(["exit"])
    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        assert con.execute("SELECT size,deleted FROM files WHERE path='recovery.txt'").fetchone() == (15, 0)
        assert con.execute("SELECT count(*) FROM file_intents").fetchone() == (0,)
        assert con.execute("SELECT count(*) FROM operations WHERE action='recovery_reconciled'").fetchone() == (1,)

    outside = Path(temp) / "outside.txt"
    outside.write_text("OUTSIDE-SENTINEL")
    (root / "outside-link").symlink_to(outside)
    output = run(["login", "student", "student-password-123",
                  "read", "outside-link", "delete", "outside-link",
                  "zip", "outside-link", "bad-link.zip", "exit"])
    assert output.count("Символические ссылки запрещены") == 3
    assert "OUTSIDE-SENTINEL" not in output
    assert outside.read_text() == "OUTSIDE-SENTINEL"
    assert not (root / "bad-link.zip").exists()

    change = root / "changing.txt"
    change.write_text("INSIDE-SENTINEL")
    stop = threading.Event()
    swaps = []

    def replace_path():
        staged = root / "next.txt"
        while not stop.is_set():
            staged.symlink_to(outside)
            staged.replace(change)
            staged.write_text("INSIDE-SENTINEL")
            staged.replace(change)
            swaps.append(1)
            stop.wait(0.001)

    worker = threading.Thread(target=replace_path)
    worker.start()
    try:
        output = run(["login", "student", "student-password-123"]
                     + ["read", "changing.txt"] * 100 + ["exit"])
    finally:
        stop.set()
        worker.join()
    assert swaps and "OUTSIDE-SENTINEL" not in output
    assert "INSIDE-SENTINEL" in output or "Символические ссылки запрещены" in output

    with sqlite3.connect(Path(temp) / "data.sqlite") as con:
        con.execute("""
            CREATE TRIGGER test_audit_fault BEFORE INSERT ON command_attempts
            WHEN NEW.command='write'
            BEGIN SELECT RAISE(ABORT,'test audit failure'); END
        """)
    assert "Работа остановлена:" in run(
        ["login", "student", "student-password-123", "write", "must-not-exist.txt", "data", ".end"],
        expected_code=1)
    assert not (root / "must-not-exist.txt").exists()

    print("Проверены: запись попытки до действия и остановка при отказе аудита.")
    print("Проверены: символьные ссылки, конкурентная подмена и блокировка второго запуска.")
    print("Проверено: восстановление метаданных после сбоя SQLite; повторный запуск идемпотентен.")
    print("Сквозная проверка пройдена.")
