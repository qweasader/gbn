# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-December/019037.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881550");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-26 12:06:09 +0530 (Wed, 26 Dec 2012)");
  script_cve_id("CVE-2012-3401", "CVE-2012-4447", "CVE-2012-4564", "CVE-2012-5581");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2012:1590");
  script_name("CentOS Update for libtiff CESA-2012:1590 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libtiff on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  A heap-based buffer overflow flaw was found in the way libtiff processed
  certain TIFF images using the Pixar Log Format encoding. An attacker could
  create a specially-crafted TIFF file that, when opened, could cause an
  application using libtiff to crash or, possibly, execute arbitrary code
  with the privileges of the user running the application. (CVE-2012-4447)

  A stack-based buffer overflow flaw was found in the way libtiff handled
  DOTRANGE tags. An attacker could use this flaw to create a
  specially-crafted TIFF file that, when opened, would cause an application
  linked against libtiff to crash or, possibly, execute arbitrary code.
  (CVE-2012-5581)

  A heap-based buffer overflow flaw was found in the tiff2pdf tool. An
  attacker could use this flaw to create a specially-crafted TIFF file that
  would cause tiff2pdf to crash or, possibly, execute arbitrary code.
  (CVE-2012-3401)

  A missing return value check flaw, leading to a heap-based buffer overflow,
  was found in the ppm2tiff tool. An attacker could use this flaw to create a
  specially-crafted PPM (Portable Pixel Map) file that would cause ppm2tiff
  to crash or, possibly, execute arbitrary code. (CVE-2012-4564)

  The CVE-2012-5581, CVE-2012-3401, and CVE-2012-4564 issues were discovered
  by Huzaifa Sidhpurwala of the Red Hat Security Response Team.

  All libtiff users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. All running applications linked
  against libtiff must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~18.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.8.2~18.el5_8", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
