# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63878");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-28 20:40:12 +0200 (Tue, 28 Apr 2009)");
  script_cve_id("CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-3794 (xpdf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

Fix several security updates in xpdf (3.02pl3 patch applied).

ChangeLog:

  * Thu Apr 16 2009 Tom spot Callaway  - 1:3.02-13

  - apply xpdf-3.02pl3 security patch to fix:
CVE-2009-0799, CVE-2009-0800, CVE-2009-1179, CVE-2009-1180
CVE-2009-1181, CVE-2009-1182, CVE-2009-1183");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update xpdf' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3794");
  script_tag(name:"summary", value:"The remote host is missing an update to xpdf
announced via advisory FEDORA-2009-3794.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495886");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495887");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495889");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495892");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495894");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495896");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=495899");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490612");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490614");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=490625");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.02~13.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xpdf-debuginfo", rpm:"xpdf-debuginfo~3.02~13.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
