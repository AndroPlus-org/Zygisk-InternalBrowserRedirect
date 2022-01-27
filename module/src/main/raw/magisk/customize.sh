DATA_PATH="/data/misc/internal_browser_redirect/userdata"
ui_print "- Magisk version: $MAGISK_VER_CODE"
if [ "$MAGISK_VER_CODE" -lt 24000 ]; then
  ui_print "*********************************************************"
  ui_print "! Please install Magisk v24+"
  abort    "*********************************************************"
fi

ui_print "- Checking arch"

if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86" ] && [ "$ARCH" != "x64" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

# Check System API Level
if [ "$API" -lt "26" ];then
  ui_print "Unsupported api version ${API}"
  abort "This module only for Android 8+"
fi

# Create userdata directory
ui_print "- Create userdata directory"
mkdir -p "$DATA_PATH"

# Set permission
ui_print "- Set permissions"
set_perm_recursive $MODPATH 0    0    0755 0644
set_perm_recursive $DATA_PATH  1000 1000 0700 0600 u:object_r:system_data_file:s0
