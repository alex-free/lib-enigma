Name: psx-piracy-patcher-example       
Version: v1.0.2
Summary: Patches LibCrypt v1 in MediEvil Europe, and patches APv2 protection for other games. APv2 patch is gaurenteed to work if it is detected, but the patching method ONLY allows these games to run on a soft-modded console WITHOUT a non-stealth mod-chip.
Release: 1
License: 3-BSD
URL: alex-free.github.io       
Packager: Alex Free
Group: Unspecified

%description
Patches LibCrypt v1 in MediEvil Europe, and patches APv2 protection for other games. APv2 patch is gaurenteed to work if it is detected, but the patching method ONLY allows these games to run on a soft-modded console WITHOUT a non-stealth mod-chip.

%install
mkdir -p %{buildroot}/usr/bin
cp %{_sourcedir}/psxpiracyp %{buildroot}/usr/bin/

%files
/usr/bin/psxpiracyp
