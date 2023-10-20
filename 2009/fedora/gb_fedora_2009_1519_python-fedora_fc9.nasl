# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63382");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-13 20:43:17 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 9 FEDORA-2009-1519 (python-fedora)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

This release includes a bugfix to the
fedora.client.AccountSystem().verify_password() method.  verify_password() was
incorrectly returning True (username, password combination was correct) for any
input.  Although no known code is using this method to verify a user's account
with the Fedora Account System, the existence of the method and the fact that
anyone using this would be allowing users due to the bug makes this a high
priority bug to fix.

ChangeLog:

  * Sun Feb  8 2009 Toshio Kuratomi  - 0.3.9-1

  - New upstream with important bugfixes.

  * Sat Nov 29 2008 Ignacio Vazquez-Abrams  - 0.3.8-2

  - Rebuild for Python 2.6

  * Thu Nov 20 2008 Toshio Kuratomi  - 0.3.8-1

  - New upstream with pycurl client backend, more fas methods, and bodhi bugfix.

  * Thu Oct 30 2008 Toshio Kuratomi  - 0.3.7-1

  - New upstream has more complete pkgdb integration.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update python-fedora' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-1519");
  script_tag(name:"summary", value:"The remote host is missing an update to python-fedora
announced via advisory FEDORA-2009-1519.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"python-fedora", rpm:"python-fedora~0.3.9~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
