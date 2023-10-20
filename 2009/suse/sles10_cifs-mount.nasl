# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65815");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
  script_cve_id("CVE-2008-4314");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:P");
  script_name("SLES10: Security update for Samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=SLES10\.0");
  script_tag(name:"solution", value:"Please install the updates provided by SuSE.");
  script_tag(name:"summary", value:"The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    cifs-mount
    libmsrpc
    libmsrpc-devel
    libsmbclient
    libsmbclient-devel
    samba
    samba-client
    samba-krb-printing
    samba-python
    samba-vscan
    samba-winbind


More details may also be found by searching for the SuSE
Enterprise Server 10 patch database linked in the references.");

  script_xref(name:"URL", value:"http://download.novell.com/patch/finder/");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"cifs-mount", rpm:"cifs-mount~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmsrpc", rpm:"libmsrpc~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmsrpc-devel", rpm:"libmsrpc-devel~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-krb-printing", rpm:"samba-krb-printing~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-vscan", rpm:"samba-vscan~0.3.6b~42.79", rls:"SLES10.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.0.32~0.6", rls:"SLES10.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
