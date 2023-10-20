# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66405");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-1888", "CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:320 (samba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in samba:

The acl_group_override function in smbd/posix_acls.c in smbd in Samba
3.0.x before 3.0.35, 3.1.x and 3.2.x before 3.2.13, and 3.3.x before
3.3.6, when dos filemode is enabled, allows remote attackers to modify
access control lists for files via vectors related to read access to
uninitialized memory (CVE-2009-1888).

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

The version of samba shipping with Mandriva Linux 2008.0 has been
updated to the latest version (3.0.37) that includes the fixes for
these issues.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:320");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2009-2813.html");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2009-2906.html");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2009-2948.html");
  script_tag(name:"summary", value:"The remote host is missing an update to samba
announced via advisory MDVSA-2009:320.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mount-cifs", rpm:"mount-cifs~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan-icap", rpm:"samba-vscan-icap~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.0.37~0.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
