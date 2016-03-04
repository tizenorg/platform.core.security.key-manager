Name:       key-manager
Summary:    Central Key Manager and utilities
Version:    0.1.21
Release:    1
Group:      System/Security
License:    Apache-2.0 and BSL-1.0 and BSD-2.0
Source0:    %{name}-%{version}.tar.gz
Source1001: key-manager-pam-plugin.manifest
Source1002: libkey-manager-client.manifest
Source1003: libkey-manager-client-devel.manifest
Source1004: libkey-manager-common.manifest
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(libsystemd-journal)
BuildRequires: pkgconfig(libxml-2.0)
BuildRequires: pkgconfig(capi-system-info)
BuildRequires: pkgconfig(security-manager)
BuildRequires: pkgconfig(cynara-client-async)
BuildRequires: pkgconfig(cynara-creds-socket)
BuildRequires: pkgconfig(libtzplatform-config)
BuildRequires: pkgconfig(glib-2.0)
BuildRequires: pkgconfig(pkgmgr)
BuildRequires: boost-devel
BuildRequires: ca-certificates-devel
#Requires(pre): tizen-platform-config-tools
Requires: libkey-manager-common = %{version}-%{release}
%{?systemd_requires}

%global user_name key-manager
%global group_name key-manager
%global service_name key-manager
%global smack_domain_name System
%global old_rw_data_dir /opt/data/ckm
%global rw_data_dir %{?TZ_SYS_DATA:%TZ_SYS_DATA/ckm}%{!?TZ_SYS_DATA:%old_rw_data_dir}
%global ro_data_dir %{?TZ_SYS_RO_SHARE:%TZ_SYS_RO_SHARE/ckm}%{!?TZ_SYS_RO_SHARE:%_datadir/ckm}
%global db_test_dir %{?TZ_SYS_RO_SHARE:%TZ_SYS_RO_SHARE/ckm-db-test}%{!?TZ_SYS_RO_SHARE:%_datadir/ckm-db-test}
%global bin_dir %{?TZ_SYS_BIN:%TZ_SYS_BIN}%{!?TZ_SYS_BIN:%_bindir}
%global sbin_dir %{?TZ_SYS_SBIN:%TZ_SYS_SBIN}%{!?TZ_SYS_SBIN:%_sbindir}
%global ro_etc_dir %{?TZ_SYS_RO_ETC:%TZ_SYS_RO_ETC}%{!?TZ_SYS_RO_ETC:/etc}
%global run_dir %{?TZ_SYS_RUN:%TZ_SYS_RUN}%{!?TZ_SYS_RUN:/var/run}
%global initial_values_dir %{rw_data_dir}/initial_values
%global ca_certs_dir %{?TZ_SYS_CA_CERTS:%TZ_SYS_CA_CERTS}%{!?TZ_SYS_CA_CERTS:%ro_etc_dir/ssl/certs}

%description
Central Key Manager daemon could be used as secure storage
for certificate and private/public keys. It gives API for
application to sign and verify (DSA/RSA/ECDSA) signatures.

%package -n libkey-manager-common
Summary:    Central Key Manager (common libraries)
Group:      Development/Libraries
Requires(post): %{sbin_dir}/ldconfig
Requires(postun): %{sbin_dir}/ldconfig

%description -n libkey-manager-common
Central Key Manager package (common library)

%package -n libkey-manager-client
Summary:    Central Key Manager (client)
Group:      Development/Libraries
Requires:   key-manager = %{version}-%{release}
Requires:   libkey-manager-common = %{version}-%{release}
Requires(post): %{sbin_dir}/ldconfig
Requires(postun): %{sbin_dir}/ldconfig

%description -n libkey-manager-client
Central Key Manager package (client)

%package -n libkey-manager-client-devel
Summary:    Central Key Manager (client-devel)
Group:      Development/Libraries
BuildRequires: pkgconfig(capi-base-common)
Requires:   pkgconfig(capi-base-common)
Requires:   libkey-manager-client = %{version}-%{release}

%description -n libkey-manager-client-devel
Central Key Manager package (client-devel)

%package -n key-manager-tests
Summary:    Internal test for key-manager
Group:      Development
BuildRequires: pkgconfig(libxml-2.0)
Requires:   boost-test
Requires:   key-manager = %{version}-%{release}

%description -n key-manager-tests
Internal test for key-manager implementation.

%package -n key-manager-pam-plugin
Summary:    CKM login/password module to PAM
Group:      Development/Libraries
BuildRequires: pam-devel
Requires:   key-manager = %{version}-%{release}
Requires(post): %{sbin_dir}/ldconfig
Requires(postun): %{sbin_dir}/ldconfig

%description -n key-manager-pam-plugin
CKM login/password module to PAM. Used to monitor user login/logout
and password change events from PAM


%prep
%setup -q
cp -a %{SOURCE1001} .
cp -a %{SOURCE1002} .
cp -a %{SOURCE1003} .
cp -a %{SOURCE1004} .

%build
%if 0%{?sec_build_binary_debug_enable}
    export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
    export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
    export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif


export LDFLAGS+="-Wl,--rpath=%{_libdir},-Bsymbolic-functions "

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON \
        -DSYSTEMD_UNIT_DIR=%{_unitdir} \
        -DSYSTEMD_ENV_FILE=%{ro_etc_dir}"/sysconfig/central-key-manager" \
        -DRUN_DIR:PATH=%{run_dir} \
        -DSERVICE_NAME=%{service_name} \
        -DUSER_NAME=%{user_name} \
        -DGROUP_NAME=%{group_name} \
        -DSMACK_DOMAIN_NAME=%{smack_domain_name} \
        -DMOCKUP_SM=%{?mockup_sm:%mockup_sm}%{!?mockup_sm:OFF} \
        -DOLD_RW_DATA_DIR=%{old_rw_data_dir} \
        -DRW_DATA_DIR=%{rw_data_dir} \
        -DRO_DATA_DIR=%{ro_data_dir} \
        -DRW_ETC_DIR=%{rw_etc_dir} \
        -DRO_ETC_DIR=%{ro_etc_dir} \
        -DBIN_DIR=%{bin_dir} \
        -DINITIAL_VALUES_DIR=%{initial_values_dir} \
        -DDB_TEST_DIR=%{db_test_dir} \
        -DCA_CERTS_DIR=%{ca_certs_dir}

make %{?jobs:-j%jobs}

%install
%make_install
%install_service multi-user.target.wants central-key-manager.service
%install_service sockets.target.wants central-key-manager-api-control.socket
%install_service sockets.target.wants central-key-manager-api-storage.socket
%install_service sockets.target.wants central-key-manager-api-ocsp.socket
%install_service sockets.target.wants central-key-manager-api-encryption.socket

%pre
# tzplatform-get sync breaked because of on-development situation. comment out just for temporary
# fail if runtime dir variable is different than compilation time variable
#if [ `tzplatform-get TZ_SYS_DATA | cut -d'=' -f2` != %{TZ_SYS_DATA} ]
#then
#    echo "Runtime value of TZ_SYS_DATA is different than the compilation time value. Aborting"
#    exit 1
#fi
#if [ `tzplatform-get TZ_SYS_RO_SHARE | cut -d'=' -f2` != %{TZ_SYS_RO_SHARE} ]
#then
#    echo "Runtime value of TZ_SYS_RO_SHARE is different than the compilation time value. Aborting"
#    exit 1
#fi

## backup plan for manage key-manager user/group is deprecated b/c pwdutils package
## would be excluded from binary
# User/group (key-manager/key-manager) should be already added in passwd package.
# This is our backup plan if passwd package will not be configured correctly.
#id -g %{group_name} > /dev/null 2>&1
#if [ $? -eq 1 ]; then
#    groupadd %{group_name} -r > /dev/null 2>&1
#fi
#
#id -u %{user_name} > /dev/null 2>&1
#if [ $? -eq 1 ]; then
#    useradd -d /var/lib/empty -s %{sbin_dir}/nologin -r -g %{group_name} %{user_name} > /dev/null 2>&1
#fi

%post
# move data from old path to new one
# we have to assume that in case of TZ_SYS_DATA change some upgrade script will move all the data
if [ -d "%{old_rw_data_dir}" ] && [ "%{rw_data_dir}" != "%{old_rw_data_dir}" ]
then
    echo "Migrating old rw data to new rw data dir"
    cp -a %{old_rw_data_dir}/. %{rw_data_dir}/ && rm -rf %{old_rw_data_dir}
fi

systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start central-key-manager.service
fi

if [ $1 = 2 ]; then
    # update

    # In ckm version <= 0.1.18 all files were owned by root.
    find %{rw_data_dir} -exec chsmack -a %{smack_domain_name} {} \;
    chown %{user_name}:%{group_name} -R %{rw_data_dir}
    systemctl restart central-key-manager.service
fi


%preun
if [ $1 = 0 ]; then
    # unistall
    systemctl stop central-key-manager.service
fi

%postun
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%post -n libkey-manager-common -p %{sbin_dir}/ldconfig
%post -n libkey-manager-client -p %{sbin_dir}/ldconfig
%postun -n libkey-manager-common -p %{sbin_dir}/ldconfig
%postun -n libkey-manager-client -p %{sbin_dir}/ldconfig

%files -n key-manager
%manifest key-manager.manifest
%license LICENSE
%license LICENSE.BSL-1.0
%license LICENSE.BSD-2.0
%{bin_dir}/key-manager
%{_unitdir}/multi-user.target.wants/central-key-manager.service
%{_unitdir}/central-key-manager.service
%{_unitdir}/central-key-manager.target
%{_unitdir}/sockets.target.wants/central-key-manager-api-control.socket
%{_unitdir}/central-key-manager-api-control.socket
%{_unitdir}/sockets.target.wants/central-key-manager-api-storage.socket
%{_unitdir}/central-key-manager-api-storage.socket
%{_unitdir}/sockets.target.wants/central-key-manager-api-ocsp.socket
%{_unitdir}/central-key-manager-api-ocsp.socket
%{_unitdir}/sockets.target.wants/central-key-manager-api-encryption.socket
%{_unitdir}/central-key-manager-api-encryption.socket
%dir %{ro_data_dir}
%{ro_data_dir}/*
%dir %attr(770, %{user_name}, %{group_name}) %{rw_data_dir}
%dir %attr(770, %{user_name}, %{group_name}) %{initial_values_dir}
%{ro_etc_dir}/opt/upgrade/230.key-manager-change-data-dir.patch.sh
%{ro_etc_dir}/opt/upgrade/231.key-manager-migrate-dkek.patch.sh
%{ro_etc_dir}/opt/upgrade/232.key-manager-change-user.patch.sh
%{ro_etc_dir}/gumd/userdel.d/10_key-manager.post
%{bin_dir}/ckm_tool

%files -n key-manager-pam-plugin
%manifest key-manager-pam-plugin.manifest
%{_libdir}/security/pam_key_manager_plugin.so*

%files -n libkey-manager-common
%manifest libkey-manager-common.manifest
%{_libdir}/libkey-manager-common.so.*

%files -n libkey-manager-client
%manifest libkey-manager-client.manifest
%license LICENSE
%{_libdir}/libkey-manager-client.so.*
%{_libdir}/libkey-manager-control-client.so.*

%files -n libkey-manager-client-devel
%manifest libkey-manager-client-devel.manifest
%{_libdir}/libkey-manager-client.so
%{_libdir}/libkey-manager-control-client.so
%{_libdir}/libkey-manager-common.so
%{_includedir}/ckm/ckm/ckm-manager.h
%{_includedir}/ckm/ckm/ckm-manager-async.h
%{_includedir}/ckm/ckm/ckm-certificate.h
%{_includedir}/ckm/ckm/ckm-control.h
%{_includedir}/ckm/ckm/ckm-error.h
%{_includedir}/ckm/ckm/ckm-key.h
%{_includedir}/ckm/ckm/ckm-password.h
%{_includedir}/ckm/ckm/ckm-pkcs12.h
%{_includedir}/ckm/ckm/ckm-raw-buffer.h
%{_includedir}/ckm/ckm/ckm-type.h
%{_includedir}/ckm/ckmc/ckmc-manager.h
%{_includedir}/ckm/ckmc/ckmc-control.h
%{_includedir}/ckm/ckmc/ckmc-error.h
%{_includedir}/ckm/ckmc/ckmc-type.h
%{_libdir}/pkgconfig/*.pc

%files -n key-manager-tests
%manifest key-manager-tests.manifest
%{bin_dir}/ckm-tests-internal
%{bin_dir}/ckm_so_loader
%{bin_dir}/ckm_db_tool
%{bin_dir}/ckm_generate_db
%db_test_dir
