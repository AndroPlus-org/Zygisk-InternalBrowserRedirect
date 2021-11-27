DATA_PATH="/data/misc/internal_browser_redirect"

ui_print "- Checking arch"

if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86" ] && [ "$ARCH" != "x64" ]; then
  abort "! Unsupported platform: $ARCH"
else
  ui_print "- Device platform: $ARCH"
fi

. $MODPATH/riru.sh

check_riru_version

# Check System API Level
if [ "$API" -lt "23" ];then
  ui_print "Unsupported api version ${API}"
  abort "This module only for Android 6+"
fi

if [ "$ARCH" = "x86" ] || [ "$ARCH" = "x64" ]; then
  rm -rf ${MODPATH}/riru
  mv "${MODPATH}/riru_x86" "${MODPATH}/riru"
else
  rm -rf ${MODPATH}/riru_x86
fi

# Remove 64-bit library
if [[ "$IS64BIT" = false ]]; then
  ui_print "- Removing 64-bit libraries"
  rm -rf "$MODPATH/riru/lib64"
fi

# Create userdata directory
ui_print "- Create userdata directory"
mkdir -p "$DATA_PATH/userdata"

# Set permission
ui_print "- Set permissions"
set_perm_recursive $MODPATH 0    0    0755 0644
set_perm_recursive $DATA_PATH  1000 1000 0700 0600 u:object_r:system_data_file:s0
