# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64306");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-1760");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-6502 (rb_libtorrent)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"Update Information:

This release adds an upstream patch to fix a directory traversal vulnerability
which would allow a remote attacker to create or overwrite arbitrary files via a
.. (dot dot) and partial relative pathname in a specially-crafted torrent.

ChangeLog:

  * Fri Jun 12 2009 Peter Gordon  - 0.14.3-2

  - Apply upstream patch to fix CVE-2009-1760 (arbitrary file overwrite
vulnerability):
+ CVE-2009-1760.diff

  - Fixes security bug #505523.

  - Drop outdated Boost patch:

  - 0.13.1-boost.patch");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update rb_libtorrent' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6502");
  script_tag(name:"summary", value:"The remote host is missing an update to rb_libtorrent
announced via advisory FEDORA-2009-6502.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=505523");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"rb_libtorrent", rpm:"rb_libtorrent~0.14.3~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rb_libtorrent-devel", rpm:"rb_libtorrent-devel~0.14.3~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rb_libtorrent-examples", rpm:"rb_libtorrent-examples~0.14.3~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rb_libtorrent-python", rpm:"rb_libtorrent-python~0.14.3~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"rb_libtorrent-debuginfo", rpm:"rb_libtorrent-debuginfo~0.14.3~2.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
