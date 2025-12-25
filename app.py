import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


DATA_FILE = "vault.json"

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))
    return key


def load_vault_file():
    if not os.path.exists(DATA_FILE):
        return None
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)
    

def save_vault_file(data: dict):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def init_vault():
    print(" أول مرة! بنسوي Vault جديد.")
    master1 = getpass.getpass("اكتبي Master Password: ")
    master2 = getpass.getpass("تأكيد Master Password: ")
    if master1 != master2 or not master1:
        print(" كلمة السر غير متطابقة أو فاضية.")
        return None
    
    salt = os.urandom(16)
    key = derive_key(master1, salt)
    fernet = Fernet(key)

    empty_entries = []
    encrypted = fernet.encrypt(json.dumps(empty_entries).encode("utf-8"))

    data = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "vault": base64.b64encode(encrypted).decode("utf-8"),
    }
    save_vault_file(data)
    print(" تم إنشاء الـ Vault بنجاح.")
    return master1


def open_vault(master_password: str):
    data = load_vault_file()
    if data is None:
        return None

    salt = base64.b64decode(data["salt"])
    encrypted = base64.b64decode(data["vault"])

    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(encrypted)
    except InvalidToken:
        return None

    entries = json.loads(decrypted.decode("utf-8"))
    return entries


def save_vault(master_password: str, entries: list):
    data = load_vault_file()
    salt = base64.b64decode(data["salt"])
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    encrypted = fernet.encrypt(json.dumps(entries, ensure_ascii=False).encode("utf-8"))
    data["vault"] = base64.b64encode(encrypted).decode("utf-8")
    save_vault_file(data)


def add_entry(entries: list):
    site = input("اسم الموقع/التطبيق: ").strip()
    username = input("اسم المستخدم/الإيميل: ").strip()
    password = getpass.getpass("كلمة المرور (للتجربة فقط): ").strip()

    if not site or not username or not password:
        print(" لازم كل الحقول.")
        return

    entries.append({"site": site, "username": username, "password": password})
    print(" تمت الإضافة.")


def list_entries(entries: list):
    if not entries:
        print("ما فيه بيانات.")
        return
    for i, e in enumerate(entries, start=1):
        print(f"{i}) {e['site']} | {e['username']}")


def search_entries(entries: list):
    q = input("اكتب كلمة بحث (اسم موقع/يوزر): ").strip().lower()
    found = []
    for i, e in enumerate(entries, start=1):
        if q in e["site"].lower() or q in e["username"].lower():
            found.append((i, e))
    if not found:
        print(" ما لقينا شيء.")
        return
    for i, e in found:
        print(f"{i}) {e['site']} | {e['username']} | (password مخفية)")


def view_password(entries: list):
    if not entries:
        print(" ما فيه بيانات.")
        return
    list_entries(entries)
    try:
        idx = int(input("اختاري رقم العنصر لعرض كلمة المرور: "))
        if idx < 1 or idx > len(entries):
            print(" رقم غلط.")
            return
        e = entries[idx - 1]
        print(f" الموقع: {e['site']}")
        print(f" المستخدم: {e['username']}")
        print(f" كلمة المرور: {e['password']}")
    except ValueError:
        print("دخلي رقم صحيح.")


def delete_entry(entries: list):
    if not entries:
        print(" ما فيه بيانات.")
        return
    list_entries(entries)
    try:
        idx = int(input("رقم العنصر اللي تبين تحذفينه: "))
        if idx < 1 or idx > len(entries):
            print(" رقم غلط.")
            return
        removed = entries.pop(idx - 1)
        print(f" تم حذف: {removed['site']}")
    except ValueError:
        print(" دخلي رقم صحيح.")


def main():
    data = load_vault_file()
    if data is None:
        master = init_vault()
        if master is None:
            return
    else:
        master = getpass.getpass("ادخلي Master Password لفتح الـ Vault: ")
        entries = open_vault(master)
        if entries is None:
            print(" كلمة المرور غلط.")
            return

    entries = open_vault(master)
    if entries is None:
        print(" مشكلة في فتح الـ Vault.")
        return

    while True:
        print("\n=== Password Manager ===")
        print("1) إضافة حساب")
        print("2) عرض القائمة")
        print("3) بحث")
        print("4) عرض كلمة مرور (للتجربة)")
        print("5) حذف")
        print("6) حفظ وخروج")
        choice = input("اختاري: ").strip()

        if choice == "1":
            add_entry(entries)
        elif choice == "2":
            list_entries(entries)
        elif choice == "3":
            search_entries(entries)
        elif choice == "4":
            view_password(entries)
        elif choice == "5":
            delete_entry(entries)
        elif choice == "6":
            save_vault(master, entries)
            print(" تم الحفظ. باي ")
            break
        else:
            print(" اختيار غير صحيح.")


if __name__ == "__main__":
    main()