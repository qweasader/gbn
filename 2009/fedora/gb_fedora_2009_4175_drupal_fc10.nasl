# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63926");
  script_version("2023-11-02T05:05:26+0000");
  script_cve_id("CVE-2009-1575", "CVE-2009-1576");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2009-05-05 16:00:35 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-4175 (drupal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"6.11, Fix for SA-CORE-2009-005.Remember to log in to your site as the admin user before
upgrading this package. After upgrading the package, browse to
http://example.com/drupal/update.php to run the upgrade script.

ChangeLog:

  * Thu Apr 30 2009 Jon Ciesla  - 6.11-1

  - Update to 6.11, SA-CORE-2009-005.

  * Mon Apr 27 2009 Jon Ciesla  - 6.10-2

  - Added SELinux/sendmail note to README, BZ 497642.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update drupal' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-4175");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34779");
  script_tag(name:"summary", value:"The remote host is missing an update to drupal
announced via advisory FEDORA-2009-4175.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=498643");
  script_xref(name:"URL", value:"http://drupal.org/node/449078");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"drupal", rpm:"drupal~6.11~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
