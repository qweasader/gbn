# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66139");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
  script_cve_id("CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3607", "CVE-2009-3608", "CVE-2009-3609");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 10 FEDORA-2009-10823 (poppler)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

This build addresses several recent security issues.

ChangeLog:

  * Sun Oct 25 2009 Rex Dieter  - 0.8.8-7

  - CVE-2009-3603 SplashBitmap::SplashBitmap integer overflow (#526915)

  - CVE-2009-3604 Splash::drawImage integer overflow and missing allocation
                return value check(#526911)

  - CVE-2009-3606 PSOutputDev::doImageL1Sep integer overflow (#526877)

  - CVE-2009-3607 create_surface_from_thumbnail_data integer overflow (#526924)

  - CVE-2009-3608 integer overflow in ObjectStream::ObjectStream (#526637)

  - CVE-2009-3609 ImageStream::ImageStream integer overflow (#526893)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update poppler' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-10823");
  script_tag(name:"summary", value:"The remote host is missing an update to poppler
announced via advisory FEDORA-2009-10823.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526915");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526911");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526877");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526924");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526637");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=526893");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-glib", rpm:"poppler-glib~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-glib-devel", rpm:"poppler-glib-devel~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt", rpm:"poppler-qt~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt-devel", rpm:"poppler-qt-devel~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt4", rpm:"poppler-qt4~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-qt4-devel", rpm:"poppler-qt4-devel~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"poppler-debuginfo", rpm:"poppler-debuginfo~0.8.7~7.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
