# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66033");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
  script_cve_id("CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:277 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1|3\.0|4\.0|mes5)");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in samba:

The SMB (aka Samba) subsystem in Apple Mac OS X 10.5.8, when Windows
File Sharing is enabled, does not properly handle errors in resolving
pathnames, which allows remote authenticated users to bypass intended
sharing restrictions, and read, create, or modify files, in certain
circumstances involving user accounts that lack home directories
(CVE-2009-2813).

smbd in Samba 3.0 before 3.0.37, 3.2 before 3.2.15, 3.3 before 3.3.8,
and 3.4 before 3.4.2 allows remote authenticated users to cause a
denial of service (infinite loop) via an unanticipated oplock break
notification reply packet (CVE-2009-2906).

mount.cifs in Samba 3.0 before 3.0.37, 3.2 before 3.2.15, 3.3 before
3.3.8 and 3.4 before 3.4.2, when mount.cifs is installed suid root,
does not properly enforce permissions, which allows local users to
read part of the credentials file and obtain the password by specifying
the path to the credentials file and using the --verbose or -v option
(CVE-2009-2948).

The versions of samba shipping with Mandriva Linux
CS4/MES5/2008.1/2009.0/2009.1 have been updated to the latest version
that includes the fixes for these issues. Additionally for 2009.1
the version upgrade provides many upstream bug fixes such as improved
Windows(tm) 7 support. The version for CS3 has been patched to address
these security issues.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:277");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2009-2813.html");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2009-2906.html");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2009-2948.html");
  script_tag(name:"summary", value:"The remote host is missing an update to samba
announced via advisory MDVSA-2009:277.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan-icap", rpm:"samba-vscan-icap~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.0.37~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc1", rpm:"libtalloc1~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc-devel", rpm:"libtalloc-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb-devel", rpm:"libtdb-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64talloc1", rpm:"lib64talloc1~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64talloc-devel", rpm:"lib64talloc-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64tdb1", rpm:"lib64tdb1~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64tdb-devel", rpm:"lib64tdb-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.2.15~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.3.8~0.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-passdb-xml", rpm:"samba-passdb-xml~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-smbldap-tools", rpm:"samba-smbldap-tools~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan-antivir", rpm:"samba-vscan-antivir~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan-clamav", rpm:"samba-vscan-clamav~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan-icap", rpm:"samba-vscan-icap~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.0.14a~6.11.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan-icap", rpm:"samba-vscan-icap~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.0.37~0.1.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc1", rpm:"libtalloc1~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtalloc-devel", rpm:"libtalloc-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb1", rpm:"libtdb1~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtdb-devel", rpm:"libtdb-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64talloc1", rpm:"lib64talloc1~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64talloc-devel", rpm:"lib64talloc-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64tdb1", rpm:"lib64tdb1~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64tdb-devel", rpm:"lib64tdb-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.2.15~0.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
