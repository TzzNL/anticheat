import uuid
import pyperclip

def get_hwid():
    """Get the hardware ID of the current machine."""
    return str(uuid.UUID(int=uuid.getnode()))

def main():
    hwid = get_hwid()
    pyperclip.copy(hwid)
    print(f"Your HWID: {hwid}")
    print("The HWID has been copied to your clipboard.")

if __name__ == "__main__":
    main()
