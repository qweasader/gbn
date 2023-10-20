# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66195");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3720");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 11 FEDORA-2009-10987 (expat)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

This update fixes a security vulnerability:
A buffer over-read flaw was found in the way Expat handles malformed UTF-8
sequences when processing XML files. A specially-crafted XML file could
cause applications using Expat to crash while parsing the file. (CVE-2009-3720)

ChangeLog:

  * Fri Oct 30 2009 Joe Orton  - 2.0.1-6.1

  - add security fix for CVE-2009-3720");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update expat' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10987");
  script_tag(name:"summary", value:"The remote host is missing an update to expat
announced via advisory FEDORA-2009-10987.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=531697");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"expat", rpm:"expat~2.0.1~6.fc11.1", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"expat-devel", rpm:"expat-devel~2.0.1~6.fc11.1", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"expat-debuginfo", rpm:"expat-debuginfo~2.0.1~6.fc11.1", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
