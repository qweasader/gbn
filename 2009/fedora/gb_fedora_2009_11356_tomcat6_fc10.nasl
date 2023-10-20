# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66330");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-03 22:10:42 +0100 (Thu, 03 Dec 2009)");
  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-11356 (tomcat6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

Fix for CVE-2008-5515, CVE-2009-0033, CVE-2009-0580, CVE-2009-0781, and
CVE-2009-0783.

ChangeLog:

  * Mon Nov  9 2009 Alexander Kurtakov  0:6.0.20-1

  - Update to 6.0.20. Fixes CVE-2009-0033, CVE-2009-0580.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update tomcat6' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-11356");
  script_tag(name:"summary", value:"The remote host is missing an update to tomcat6
announced via advisory FEDORA-2009-11356.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=533903");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.20~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.20~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.20~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.20~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat6-jsp-2.1", rpm:"tomcat6-jsp-2.1~api~6.0.20", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.20~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat6-servlet-2.5", rpm:"tomcat6-servlet-2.5~api~6.0.20", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.20~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
