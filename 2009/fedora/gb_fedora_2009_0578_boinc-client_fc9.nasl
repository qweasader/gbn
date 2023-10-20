# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63325");
  script_version("2023-07-18T05:05:36+0000");
  script_cve_id("CVE-2009-0126");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-02-10 15:52:40 +0100 (Tue, 10 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 9 FEDORA-2009-0578 (boinc-client)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC9");
  script_tag(name:"insight", value:"The Berkeley Open Infrastructure for Network Computing (BOINC) is an open-
source software platform which supports distributed computing, primarily in
the form of volunteer computing and desktop Grid computing.  It is well
suited for problems which are often described as trivially parallel.  BOINC
is the underlying software used by projects such as SETI@home, Einstein@Home,
ClimatePrediciton.net, the World Community Grid, and many other distributed
computing projects.

This package installs the BOINC client software, which will allow your
computer to participate in one or more BOINC projects, using your spare
computer time to search for cures for diseases, model protein folding, study
global warming, discover sources of gravitational waves, and many other types
of scientific and mathematical research.

Update Information:

  - Fix security bug BZ#479664 - Update to 6.4.5

ChangeLog:

  * Thu Jan 15 2009 Milos Jakubicek  - 6.4.5-2.20081217svn

  - Fix security bug BZ#479664

  * Wed Dec 17 2008 Milos Jakubicek  - 6.4.5-1.20081217svn

  - Update to 6.4.5

  - Updated boinc-gccflags.patch and boinc-locales.patch

  - Not trimming doc/ subdirectory

  - Bash completion now provided by the source tarball,
  not packaged as separate sources anymore.

  - Supplied example /etc/sysconfig configuration file

  - Added BR: docbook2X for autogenerating manpages, not packaged as separate
  sources anymore.");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update boinc-client' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-0578");
  script_tag(name:"summary", value:"The remote host is missing an update to boinc-client
announced via advisory FEDORA-2009-0578.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479664");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"boinc-client", rpm:"boinc-client~6.4.5~2.20081217svn.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"boinc-client-devel", rpm:"boinc-client-devel~6.4.5~2.20081217svn.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"boinc-manager", rpm:"boinc-manager~6.4.5~2.20081217svn.fc9", rls:"FC9")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"boinc-client-debuginfo", rpm:"boinc-client-debuginfo~6.4.5~2.20081217svn.fc9", rls:"FC9")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
