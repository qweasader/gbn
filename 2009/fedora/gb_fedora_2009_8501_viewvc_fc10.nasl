# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64628");
  script_cve_id("CVE-2009-3618", "CVE-2009-3619");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 10 FEDORA-2009-8501 (viewvc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC10");
  script_tag(name:"insight", value:"Update Information:

CHANGES in 1.0.9:

  - security fix: validate the 'view' parameter to avoid XSS attack

  - security fix: avoid printing illegal parameter names and values
Also includes:
Patch by Patrick Monnerat to make allow_tar work on F-10.

ChangeLog:

  * Wed Aug 12 2009 Bojan Smojver  - 1.0.9-1

  - bump up to 1.0.9

  - security fix: validate the 'view' parameter to avoid XSS attack

  - security fix: avoid printing illegal parameter names and values

  * Tue Aug 11 2009 Bojan Smojver  - 1.0.8-2

  - fix allow_tar

  - patch by Patrick Monnerat");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update viewvc' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8501");
  script_tag(name:"summary", value:"The remote host is missing an update to viewvc
announced via advisory FEDORA-2009-8501.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513006");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"viewvc", rpm:"viewvc~1.0.9~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"viewvc-httpd", rpm:"viewvc-httpd~1.0.9~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
