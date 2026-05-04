Name: psx-bin-boot-file-printer       
Version: v1.0.3
Summary: Prints boot file name of a PSX CD image.
Release: 1
License: 3-BSD
URL: alex-free.github.io       
Packager: Alex Free
Group: Unspecified

%description
Prints boot file name of a PSX CD image.

%install
mkdir -p %{buildroot}/usr/bin
cp %{_sourcedir}/psxbp %{buildroot}/usr/bin/

%files
/usr/bin/psxbp
