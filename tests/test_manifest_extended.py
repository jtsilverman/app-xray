"""Extended tests for manifest module -- _classify_permission."""

from app_xray.extractors.manifest import _classify_permission


def test_classify_dangerous_permission():
    assert _classify_permission("android.permission.CAMERA") == "dangerous"


def test_classify_dangerous_location():
    assert _classify_permission("android.permission.ACCESS_FINE_LOCATION") == "dangerous"


def test_classify_normal_permission():
    assert _classify_permission("android.permission.INTERNET") == "normal"


def test_classify_normal_wifi():
    assert _classify_permission("android.permission.ACCESS_WIFI_STATE") == "normal"


def test_classify_custom_permission_as_signature():
    assert _classify_permission("com.example.myapp.CUSTOM_PERMISSION") == "signature"


def test_classify_another_custom():
    assert _classify_permission("org.thirdparty.SPECIAL") == "signature"


def test_classify_all_dangerous_permissions():
    """Every entry in DANGEROUS_PERMISSIONS should classify as dangerous."""
    from app_xray.extractors.manifest import DANGEROUS_PERMISSIONS
    for perm in DANGEROUS_PERMISSIONS:
        assert _classify_permission(perm) == "dangerous", f"{perm} should be dangerous"


def test_classify_foreground_service_normal():
    """FOREGROUND_SERVICE is android.permission.* but not dangerous."""
    assert _classify_permission("android.permission.FOREGROUND_SERVICE") == "normal"
