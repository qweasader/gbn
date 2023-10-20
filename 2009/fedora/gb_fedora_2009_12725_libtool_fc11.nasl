# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66572");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-30 21:58:43 +0100 (Wed, 30 Dec 2009)");
  script_cve_id("CVE-2009-3736");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-12725 (libtool)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"ChangeLog:

  * Thu Dec  3 2009 Karsten Hopp  2.2.6-11.3

  - require gcc-4.4.1 from F-11-updates

  * Wed Dec  2 2009 Karsten Hopp  2.2.6-11.2

  - update to 2.2.6b, fixes CVE-2009-3736:
libltdl may load and execute code from a library in the current directory");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libtool' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12725");
  script_tag(name:"summary", value:"The remote host is missing an update to libtool
announced via advisory FEDORA-2009-12725.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=537941");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"libtool", rpm:"libtool~2.2.6~11.fc11.3", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtool-ltdl", rpm:"libtool-ltdl~2.2.6~11.fc11.3", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtool-ltdl-devel", rpm:"libtool-ltdl-devel~2.2.6~11.fc11.3", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtool-debuginfo", rpm:"libtool-debuginfo~2.2.6~11.fc11.3", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
