# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64474");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 19:28:37 +0200 (Wed, 29 Jul 2009)");
  script_cve_id("CVE-2009-1725", "CVE-2009-1690", "CVE-2009-1687", "CVE-2009-1698", "CVE-2009-2537");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Fedora Core 11 FEDORA-2009-8046 (kdelibs3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

This update fixes several security issues in the KDE 3 compatibility version of
KHTML (CVE-2009-1725, CVE-2009-1690, CVE-2009-1687, CVE-2009-1698,
CVE-2009-2537) which may lead to a denial of service or potentially even
arbitrary code execution.    In addition, the package was fixed to build with
the latest version of automake.

ChangeLog:

  * Sun Jul 26 2009 Kevin Kofler  - 3.5.10-13

  - fix CVE-2009-2537 - select length DoS

  - fix CVE-2009-1725 - crash, possible ACE in numeric character references

  - fix CVE-2009-1690 - crash, possible ACE in KHTML ( use-after-free)

  - fix CVE-2009-1687 - possible ACE in KJS (FIXME: still crashes?)

  - fix CVE-2009-1698 - crash, possible ACE in CSS style attribute handling

  * Fri Jul 24 2009 Fedora Release Engineering  - 3.5.10-12


  * Sat Jul 18 2009 Rex Dieter  - 3.5.10-12

  - FTBFS kdelibs3-3.5.10-11.fc11 (#511571)

  - -devel: Requires: %{name}%_isa");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update kdelibs3' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8046");
  script_tag(name:"summary", value:"The remote host is missing an update to kdelibs3
announced via advisory FEDORA-2009-8046.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513813");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=505571");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=506453");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=506469");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=512911");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"kdelibs3", rpm:"kdelibs3~3.5.10~13.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3-devel", rpm:"kdelibs3-devel~3.5.10~13.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3-debuginfo", rpm:"kdelibs3-debuginfo~3.5.10~13.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdelibs3-apidocs", rpm:"kdelibs3-apidocs~3.5.10~13.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
