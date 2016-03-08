Name:       libkey-base
Summary:    Central Key Manager and utilities
Version:    0.1.20
Release:    1
Group:      System/Security
License:    Apache-2.0 and BSL-1.0
Source0:    %{name}-%{version}.tar.gz
Source1002: libkey-manager-client.manifest
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(cynara-base)

%description
Central Key Manager daemon could be used as secure storage
for certificate and private/public keys. It gives API for
application to sign and verify (DSA/RSA/ECDSA) signatures.

%package -n libkey-base-devel
Summary:    Key base development files

%description -n libkey-base-devel
Key base development files

%prep
%setup -q
cp -a %{SOURCE1002} .

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DSYSTEMD_UNIT_DIR=%{_unitdir} \
        -DSYSTEMD_ENV_FILE="/etc/sysconfig/central-key-manager" \
        -DRUN_DIR:PATH=%{_rundir} \
        -DSERVICE_NAME=%{service_name} \
        -DUSER_NAME=%{user_name} \
        -DGROUP_NAME=%{group_name} \
        -DSMACK_DOMAIN_NAME=%{smack_domain_name} \
        -DMOCKUP_SM=%{?mockup_sm:%mockup_sm}%{!?mockup_sm:OFF} \
        -DRW_DATA_DIR=%{rw_data_dir} \
        -DRO_DATA_DIR=%{ro_data_dir} \
        -DINITIAL_VALUES_DIR=%{initial_values_dir} \
        -DDB_TEST_DIR=%{db_test_dir}

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}

%make_install

%clean
rm -rf %{buildroot}

%post -n libkey-base -p /sbin/ldconfig

%postun -n libkey-base -p /sbin/ldconfig

%files -n libkey-base-devel
%{_includedir}/*.h
%{_libdir}/pkgconfig/*
%{_libdir}/*.so

%files -n libkey-base
%manifest libkey-manager-client.manifest
%{_libdir}/*.so.*

