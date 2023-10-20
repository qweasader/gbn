# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64238");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-06-23 15:49:15 +0200 (Tue, 23 Jun 2009)");
  script_cve_id("CVE-2009-2042");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Fedora Core 11 FEDORA-2009-6506 (libpng)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC11");
  script_tag(name:"insight", value:"The libpng package contains a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.  PNG
is a bit-mapped graphics format similar to the GIF format.  PNG was
created to replace the GIF format, since GIF uses a patented data
compression algorithm.

Libpng should be installed if you need to manipulate PNG format image
files.

Update Information:

Update to libpng 1.2.37, to fix CVE-2009-2042.  This is a pretty low-risk issue,
but it's been classified as a security issue...

ChangeLog:

  * Sat Jun 13 2009 Tom Lane  2:1.2.37-1

  - Update to libpng 1.2.37, to fix CVE-2009-2042
Related: #504782");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update libpng' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-6506");
  script_tag(name:"summary", value:"The remote host is missing an update to libpng
announced via advisory FEDORA-2009-6506.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=504782");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";

if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.37~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.37~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-static", rpm:"libpng-static~1.2.37~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.2.37~1.fc11", rls:"FC11")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
