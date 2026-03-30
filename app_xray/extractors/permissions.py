"""Declared vs used permission analysis."""

from app_xray.models import Permission

# Maps Android permissions to the API classes/methods that require them.
# A permission is "used" if any of its associated APIs appear in the bytecode.
PERMISSION_API_MAP = {
    "android.permission.CAMERA": [
        "android.hardware.Camera",
        "android.hardware.camera2.CameraManager",
        "androidx.camera.core",
    ],
    "android.permission.ACCESS_FINE_LOCATION": [
        "android.location.LocationManager",
        "com.google.android.gms.location",
        "getLastKnownLocation",
        "requestLocationUpdates",
    ],
    "android.permission.ACCESS_COARSE_LOCATION": [
        "android.location.LocationManager",
        "com.google.android.gms.location",
        "getLastKnownLocation",
    ],
    "android.permission.ACCESS_BACKGROUND_LOCATION": [
        "requestLocationUpdates",
        "com.google.android.gms.location",
    ],
    "android.permission.READ_CONTACTS": [
        "android.provider.ContactsContract",
        "ContactsContract",
    ],
    "android.permission.WRITE_CONTACTS": [
        "android.provider.ContactsContract",
        "ContactsContract",
    ],
    "android.permission.READ_PHONE_STATE": [
        "android.telephony.TelephonyManager",
        "getDeviceId",
        "getImei",
        "getLine1Number",
        "getSubscriberId",
    ],
    "android.permission.CALL_PHONE": [
        "android.intent.action.CALL",
        "ACTION_CALL",
    ],
    "android.permission.READ_CALL_LOG": [
        "android.provider.CallLog",
        "CallLog.Calls",
    ],
    "android.permission.READ_SMS": [
        "android.provider.Telephony.Sms",
        "Telephony.Sms",
    ],
    "android.permission.SEND_SMS": [
        "android.telephony.SmsManager",
        "SmsManager",
    ],
    "android.permission.RECEIVE_SMS": [
        "android.provider.Telephony.SMS_RECEIVED",
        "SMS_RECEIVED",
    ],
    "android.permission.RECORD_AUDIO": [
        "android.media.MediaRecorder",
        "android.media.AudioRecord",
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        "android.provider.MediaStore",
        "Environment.getExternalStorageDirectory",
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        "android.provider.MediaStore",
        "Environment.getExternalStorageDirectory",
    ],
    "android.permission.READ_CALENDAR": [
        "android.provider.CalendarContract",
        "CalendarContract",
    ],
    "android.permission.WRITE_CALENDAR": [
        "android.provider.CalendarContract",
        "CalendarContract",
    ],
    "android.permission.BODY_SENSORS": [
        "android.hardware.SensorManager",
        "Sensor.TYPE_HEART_RATE",
    ],
    "android.permission.ACTIVITY_RECOGNITION": [
        "com.google.android.gms.location.ActivityRecognition",
        "ActivityRecognitionClient",
    ],
    "android.permission.BLUETOOTH_CONNECT": [
        "android.bluetooth.BluetoothDevice",
        "BluetoothAdapter",
        "BluetoothGatt",
    ],
    "android.permission.BLUETOOTH_SCAN": [
        "android.bluetooth.le.BluetoothLeScanner",
        "startScan",
        "BluetoothAdapter.startDiscovery",
    ],
    "android.permission.POST_NOTIFICATIONS": [
        "android.app.NotificationManager",
        "NotificationCompat",
        "notify(",
    ],
    "android.permission.GET_ACCOUNTS": [
        "android.accounts.AccountManager",
        "getAccounts",
    ],
}


def analyze_permission_usage(permissions: list[Permission], dx) -> list[Permission]:
    """Cross-reference declared permissions with actual API usage in bytecode."""
    # Build a set of all strings in the bytecode for fast lookup
    all_strings = set()
    for s in dx.get_strings():
        all_strings.add(str(s.get_value()))

    # Also collect all class names
    class_names = set()
    for cls in dx.get_classes():
        name = cls.name
        if name.startswith("L") and name.endswith(";"):
            name = name[1:-1].replace("/", ".")
        class_names.add(name)

    searchable = all_strings | class_names

    updated = []
    for perm in permissions:
        api_patterns = PERMISSION_API_MAP.get(perm.name, [])
        used = False
        for pattern in api_patterns:
            for s in searchable:
                if pattern in s:
                    used = True
                    break
            if used:
                break

        updated.append(Permission(
            name=perm.name,
            protection_level=perm.protection_level,
            declared=perm.declared,
            used_in_code=used,
            description=perm.description,
        ))

    return updated
