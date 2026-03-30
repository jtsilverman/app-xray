"""AndroidManifest.xml parsing and permission extraction."""

from app_xray.models import Permission

# Android dangerous permissions (require runtime approval)
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
}

PERMISSION_DESCRIPTIONS = {
    "android.permission.CAMERA": "Access device camera",
    "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location",
    "android.permission.ACCESS_COARSE_LOCATION": "Approximate location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Location when app is in background",
    "android.permission.READ_CONTACTS": "Read contact list",
    "android.permission.WRITE_CONTACTS": "Modify contacts",
    "android.permission.READ_PHONE_STATE": "Read phone number, IMEI, carrier info",
    "android.permission.CALL_PHONE": "Make phone calls",
    "android.permission.READ_CALL_LOG": "Read call history",
    "android.permission.READ_SMS": "Read text messages",
    "android.permission.SEND_SMS": "Send text messages",
    "android.permission.RECEIVE_SMS": "Intercept incoming SMS",
    "android.permission.RECORD_AUDIO": "Record audio via microphone",
    "android.permission.READ_EXTERNAL_STORAGE": "Read files on device",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write files on device",
    "android.permission.INTERNET": "Full network access",
    "android.permission.ACCESS_WIFI_STATE": "View Wi-Fi connections",
    "android.permission.BLUETOOTH_CONNECT": "Connect to paired Bluetooth devices",
    "android.permission.POST_NOTIFICATIONS": "Send notifications",
    "android.permission.FOREGROUND_SERVICE": "Run foreground services",
    "android.permission.BODY_SENSORS": "Access body sensors (heart rate, etc.)",
    "android.permission.ACTIVITY_RECOGNITION": "Detect physical activity",
    "android.permission.GET_ACCOUNTS": "Find accounts on device",
    "android.permission.READ_CALENDAR": "Read calendar events",
    "android.permission.WRITE_CALENDAR": "Modify calendar events",
}


def _classify_permission(perm_name: str) -> str:
    """Classify a permission as dangerous, normal, or signature."""
    if perm_name in DANGEROUS_PERMISSIONS:
        return "dangerous"
    if perm_name.startswith("android.permission."):
        return "normal"
    # Custom app permissions are typically signature level
    return "signature"


def extract_permissions(apk) -> list[Permission]:
    """Extract and categorize all declared permissions from an APK."""
    raw_perms = apk.get_permissions()
    permissions = []
    for perm in raw_perms:
        level = _classify_permission(perm)
        desc = PERMISSION_DESCRIPTIONS.get(perm, "")
        permissions.append(Permission(
            name=perm,
            protection_level=level,
            declared=True,
            used_in_code=False,
            description=desc,
        ))
    # Sort: dangerous first, then normal, then signature
    order = {"dangerous": 0, "normal": 1, "signature": 2}
    permissions.sort(key=lambda p: (order.get(p.protection_level, 3), p.name))
    return permissions
