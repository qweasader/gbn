# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66503");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-1904", "CVE-2008-3790");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Fedora Core 10 FEDORA-2009-13066 (ruby)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Update to 1.8.6 p368    This package also fixes the build failure on arm

  - gnueabi systems (bug 506233), and DOS vulnerability issue on BigDecimal method
(bug 504958, CVE-2009-1904)

ChangeLog:

  * Mon Dec  7 2009 Mamoru Tasaka  - 1.8.6.386-2

  - Patch for bigdecimal DOS issue (CVE-2009-1904, bug 504958)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update ruby' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-13066");
  script_tag(name:"summary", value:"The remote host is missing an update to ruby
announced via advisory FEDORA-2009-13066.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-ri", rpm:"ruby-ri~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ruby-debuginfo", rpm:"ruby-debuginfo~1.8.6.368~2.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
