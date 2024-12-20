# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63528");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-13 19:24:56 +0100 (Fri, 13 Mar 2009)");
  script_cve_id("CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 9 FEDORA-2009-2421 (firefox)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"Update Information:

Update to the new upstream Firefox 3.0.7 / XULRunner 1.9.0.7 fixing multiple
security issues.

This update also contains new builds of all applications depending on
Gecko libraries, built against the new version.

Note: after the updated packages are installed, Firefox must be
restarted for the update to take effect.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update firefox' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-2421");
  script_tag(name:"summary", value:"The remote host is missing an update to firefox
announced via advisory FEDORA-2009-2421.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488272");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488273");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488276");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488283");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488287");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488290");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=488292");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.7~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.0.7~1.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
