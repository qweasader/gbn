# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64854");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
  script_cve_id("CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-9494 (epiphany)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Update to new upstream Firefox version 3.0.14, fixing multiple security issues.

Update also includes all packages depending on gecko-libs rebuilt
against new version of Firefox / XULRunner.

ChangeLog:

  * Wed Sep  9 2009 Jan Horak  - 2.24.3-10

  - Rebuild against newer gecko");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update epiphany' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-9494");
  script_tag(name:"summary", value:"The remote host is missing an update to epiphany
announced via advisory FEDORA-2009-9494.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521686");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521687");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521688");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521690");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521691");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521692");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521693");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521694");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=521695");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.24.3~10.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.24.3~10.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-debuginfo", rpm:"epiphany-debuginfo~2.24.3~10.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
