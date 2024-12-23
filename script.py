import ctypes
import psutil
import os
import requests
import uuid
import atexit
import time
import win32evtlog  # Importing for Event Viewer access

PROCESS_ALL_ACCESS = 0x1F0FFF

def get_hwid():
    """Get the hardware ID of the current machine."""
    return str(uuid.UUID(int=uuid.getnode()))

def send_log_to_discord(webhook_url, message):
    """Send a log message to a Discord webhook."""
    if not webhook_url:
        print("No webhook URL provided.")
        return

    data = {
        "content": message
    }

    try:
        response = requests.post(webhook_url, json=data)
        if response.status_code == 204:
            print("Log sent to Discord successfully.")
        else:
            print(f"Failed to send log to Discord: {response.status_code}")
    except Exception as e:
        print(f"Error sending log to Discord: {e}")

def read_strings_from_file(file_path):
    """Reads strings from a text file, one per line."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return []
    with open(file_path, "r") as file:
        return [line.strip() for line in file if line.strip()]


def search_memory_for_strings(pid, strings):
    """Search the memory of a process for specific strings."""
    process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process_handle:
        print(f"Failed to open process with PID {pid}")
        return []

    buffer = ctypes.create_string_buffer(4096)
    bytes_read = ctypes.c_size_t(0)

    memory_range_start = 0x1000
    memory_range_end = 0x7FFFFFFF  # Adjust as necessary for your target system

    found_strings = []

    try:
        for address in range(memory_range_start, memory_range_end, 4096):
            if ctypes.windll.kernel32.ReadProcessMemory(
                process_handle,
                ctypes.c_void_p(address),
                buffer,
                ctypes.sizeof(buffer),
                ctypes.byref(bytes_read)
            ):
                for string in strings:
                    if string.encode() in buffer.raw:
                        found_strings.append((string, hex(address)))
    except Exception as e:
        print(f"Error scanning memory: {e}")
    finally:
        ctypes.windll.kernel32.CloseHandle(process_handle)
    
    return found_strings

def send_results_to_discord(webhook_url, autoban_results, get_hwid):
    """Send the autoban and warning results to a Discord webhook."""
    if not webhook_url:
        print("No webhook URL provided.")
        return

    logs_message = (
        "\nLogs triggered for the following strings:\n" +
        "\n".join([f"'{string}' found at address {address}" for string, address in autoban_results])
        if autoban_results else "No autoban detections."
    )

    data = {
         "content": f"Memory Scan Results:\n\nHWID: {get_hwid}\n\n{logs_message}"
    }

    try:
        response = requests.post(webhook_url, json=data)
        if response.status_code == 204:
            print("Results sent to Discord successfully.")
        else:
            print(f"Failed to send results to Discord: {response.status_code}")
    except Exception as e:
        print(f"Error sending results to Discord: {e}")


def main():
    strings_file = "./strings.txt"
    webhook_url = "https://discord.com/api/webhooks/1319142135378743378/s08Y-FQeySw-NQ1ybh4ITVButdJJoaffIRX-FUP1NgxVmvcwVNTFi7kRTeIlD2EUzkke"

    # Get the expected HWID from the user
    expected_hwid = input("Enter the expected HWID to verify: ")
    current_hwid = get_hwid()

    print(f"Current HWID: {current_hwid}") 

    # Verify HWID
    if current_hwid != expected_hwid:
        print("HWID mismatch. Exiting program.")
        send_log_to_discord(webhook_url, f"User attempted to access with HWID: {current_hwid} (access denied).")
        return

    print("HWID verified successfully.")
    send_log_to_discord(webhook_url, f"User connected with HWID: {current_hwid}.")

    # Register exit log to be sent when the program closes
    def on_exit():
        send_log_to_discord(webhook_url, f"User with HWID: {current_hwid} disconnected.")

    atexit.register(on_exit)

    autoban_strings = read_strings_from_file(strings_file)

    if not autoban_strings :
        print("No strings to search for.")
        return

    # Check if fivem.exe is running
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() == 'fivem.exe':
            print("Please close FiveM before running this program.")
            send_log_to_discord(webhook_url, "FiveM.exe was detected running. User was advised to close it.")
            return

    # Find the explorer.exe process
    explorer_pid = None
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == 'explorer.exe':
            explorer_pid = proc.info['pid']
            break

    if explorer_pid is None:
        print("explorer.exe not running. Exiting program.")
        send_log_to_discord(webhook_url, "explorer.exe process not found. Exiting program.")
        return

    print(f"Found explorer.exe with PID: {explorer_pid}")

    # Define scan interval (5 minutes = 300 seconds)
    scan_interval = 300  # 5 minutes (in seconds)

    while True:
        print("Starting memory scan...")

        # Scan the memory for autoban and warning strings simultaneously
        combined_results = search_memory_for_strings(
            explorer_pid, autoban_strings 
        )

        autoban_results = [(s, addr) for s, addr in combined_results if s in autoban_strings]
        # Handle autoban results
        if autoban_results:
            print("Autoban triggered:")
            for string, address in autoban_results:
                print(f"'{string}' found at address {address}")

            # Send the autoban results to Discord immediately
            send_results_to_discord(webhook_url, autoban_results, [])

        """Monitor the Event Viewer for third-party program entries and send warnings."""
        log_type = 'Microsoft-Windows-PowerShell/Operational'  # You can change the log type depending on your requirements (e.g., Application)
        
        # Specify third-party program names or event IDs to track
        suspicious_sources = ['ThirdPartyProgramName', 'SomeSuspiciousApp']
        suspicious_event_ids = [4104]  # ScriptBlock event ID, for example

        # Open the Event Viewer logs
        try:
            print("Monitoring Event Viewer for suspicious activities...")

            # Read the event logs
            hand = win32evtlog.OpenEventLog(None, log_type)
            events = win32evtlog.ReadEventLog(hand, win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)

            for event in events:
                event_id = event.EventID
                event_source = event.SourceName

                # Check if any suspicious event is found
                if event_source in suspicious_sources or event_id in suspicious_event_ids:
                    message = f"Suspicious Event Detected!\nSource: {event_source}\nEvent ID: {event_id}\nDescription: {event.StringInserts}"
                    send_log_to_discord(webhook_url, message)
                    print(f"Suspicious event detected: {event_source} - ID: {event_id}")
                    
        except Exception as e:
            print(f"Error reading Event Viewer: {e}")
        
        # Wait for the next scan (5 minutes)
        print(f"Waiting for {scan_interval / 60} minutes before the next scan...")
        time.sleep(scan_interval)

if __name__ == "__main__":
    main()