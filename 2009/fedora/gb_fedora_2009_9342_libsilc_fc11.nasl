# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64849");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_cve_id("CVE-2008-7160");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-9342 (libsilc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"SILC Client Library libraries for clients to connect to SILC networks.

SILC (Secure Internet Live Conferencing) is a protocol which provides
secure conferencing services on the Internet over insecure channel.

ChangeLog:

  * Fri Sep  4 2009 Stu Tomlinson  1.1.8-7

  - Backport patch to fix stack corruption (CVE-2008-7160) (#521256)

  * Fri Sep  4 2009 Stu Tomlinson  1.1.8-6

  - Backport patch to fix additional string format vulnerabilities (#515648)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libsilc' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9342");
  script_tag(name:"summary", value:"The remote host is missing an update to libsilc
announced via advisory FEDORA-2009-9342.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515648");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521256");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"libsilc", rpm:"libsilc~1.1.8~7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsilc-devel", rpm:"libsilc-devel~1.1.8~7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsilc-doc", rpm:"libsilc-doc~1.1.8~7.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libsilc-debuginfo", rpm:"libsilc-debuginfo~1.1.8~7.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
