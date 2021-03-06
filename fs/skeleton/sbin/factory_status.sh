#!/bin/sh

echo "$(serial)"
echo "$(cat /tmp/platform)"
echo "$(hnvram -r GPN 2>&1)"

echo

if [ -e /tmp/gpio/ledcontrol/secure_boot ]; then
  echo "CPU is locked"
else
  echo "CPU is unlocked"
fi

if [ "$(kernopt debug)" = 1 ] || [ "$(kernopt login)" = 1 ]; then
  echo "bootloader serial port enabled"
elif [ -e /tmp/DEBUG ]; then
  echo "Linux serial port enabled"
else
  echo "Serial port disabled"
fi

if [ -e /tmp/DEBUG ]; then
  echo "DEBUG enabled"
else
  echo "DEBUG disabled"
fi

if [ "$(kernopt factory)" = 1 ]; then
  echo "Factory=1 enabled"
else
  echo "Factory=1 disabled"
fi

if [ "$(kernopt wifical)" = 1 ]; then
  echo "Wifi calibration enabled"
else
  echo "Wifi calibration disabled"
fi

echo

do_print_certificate=0
ssl="$(hnvram -qr GOOGLE_SSL_CRT 2>&1)"
if [ "$?" -eq 0 ]; then
  echo GOOGLE_SSL_CRT is populated
  do_print_certificate=1
else
  echo GOOGLE_SSL_CRT is not populated
fi

ssl="$(hnvram -qr GOOGLE_SSL_PEM 2>&1)"
if [ "$?" -eq 0 ]; then
  echo GOOGLE_SSL_PEM is populated
else
  echo GOOGLE_SSL_PEM is not populated
fi

if [ -n "$do_print_certificate" ]; then
  echo "GOOGLE_SSL_CRT:"
  echo "$(hnvram -qr GOOGLE_SSL_CRT 2>&1)"
fi

echo

echo "$(hnvram -r MAC_ADDR 2>&1)"
echo "$(hnvram -r MAC_ADDR_MOCA 2>&1)"
echo "$(hnvram -r MAC_ADDR_BT 2>&1)"
echo "$(hnvram -r MAC_ADDR_WIFI 2>&1)"
echo "$(hnvram -r MAC_ADDR_WIFI2 2>&1)"
echo "$(hnvram -r MAC_ADDR_WAN 2>&1)"
echo "SW=$(cat /etc/version 2>&1)"
echo

for path in /sys/block/sd*/device; do
  if [ ! -e "$path" ]; then
    continue
  fi
  if realpath $path | grep -q -e "/usb[0-9]*/"; then
    continue
  fi
  dev=$(basename $(dirname $path))
  serial=$(smartctl -i /dev/$dev | grep "Serial Number")
  echo "$dev: $serial"
  smartctl -A "/dev/$dev" | while read line; do
    echo "$dev: $line"
  done
done

if runnable /chroot/chromeos/bin/cryptohome ; then
	chroot /chroot/chromeos cryptohome --action=status
	chroot /chroot/chromeos cryptohome --action=tpm_status
	chroot /chroot/chromeos cryptohome --action=tpm_more_status
fi

uitype="$(hnvram -qr UITYPE 2>&1)"
if [ "$?" -eq 0 ]; then
  echo "UITYPE=$uitype"
else
  echo UITYPE=
fi

echo
