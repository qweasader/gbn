# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66291");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
  script_cve_id("CVE-2009-3639");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 10 FEDORA-2009-11666 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

This update fixes CVE-2009-3639, in which proftpd's mod_tls, when the
dNSNameRequired TLS option is enabled, does not properly handle a '\0' character
in a domain name in the Subject Alternative Name field of an X.509 client
certificate. This allows remote attackers to bypass intended client-hostname
restrictions via a crafted certificate issued by a legitimate Certification
Authority.

ChangeLog:

  * Wed Oct 21 2009 Paul Howarth  1.3.2b-1

  - Update to 1.3.2b

  - Fixed regression causing command-line define options not to work (bug 3221)

  - Fixed SSL/TLS cert subjectAltName verification (bug 3275, CVE-2009-3639)

  - Use correct cached user values with SQLNegativeCache on (bug 3282)

  - Fix slower transfers of multiple small files (bug 3284)

  - Support MaxTransfersPerHost, MaxTransfersPerUser properly (bug 3287)

  - Handle symlinks to directories with trailing slashes properly (bug 3297)

  - Drop upstreamed defines patch (bug 3221)");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update proftpd' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-11666");
  script_tag(name:"summary", value:"The remote host is missing an update to proftpd
announced via advisory FEDORA-2009-11666.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530719");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.2b~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-ldap", rpm:"proftpd-ldap~1.3.2b~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mysql", rpm:"proftpd-mysql~1.3.2b~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-postgresql", rpm:"proftpd-postgresql~1.3.2b~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-debuginfo", rpm:"proftpd-debuginfo~1.3.2b~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
