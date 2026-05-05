Name: kings-field-eng-translation-patcher       
Version: v1.0.4
Summary: Translates the original Japanese release of
Release: 1
License: 3-BSD
URL: alex-free.github.io       
Packager: Alex Free
Group: Unspecified

%description
Translates the original Japanese release of

%install
mkdir -p %{buildroot}/usr/bin
cp %{_sourcedir}/kfeng %{buildroot}/usr/bin/

%files
/usr/bin/kfeng
