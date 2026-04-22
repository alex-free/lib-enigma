Name: sector-view       
Version: v1.0.2
Summary: View sector data in cd images.
Release: 1
License: 3-BSD
URL: alex-free.github.io       
Packager: Alex Free
Group: Unspecified

%description
View sector data in cd images.

%install
mkdir -p %{buildroot}/usr/bin
cp %{_sourcedir}/secviewer %{buildroot}/usr/bin/

%files
/usr/bin/secviewer
