# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00034.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870524");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-16 11:08:49 +0530 (Fri, 16 Dec 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2011:1811-01");
  script_cve_id("CVE-2009-4274", "CVE-2011-4516", "CVE-2011-4517");
  script_name("RedHat Update for netpbm RHSA-2011:1811-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netpbm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(5|4)");
  script_tag(name:"affected", value:"netpbm on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The netpbm packages contain a library of functions which support programs
  for handling various graphics file formats, including .pbm (Portable Bit
  Map), .pgm (Portable Gray Map), .pnm (Portable Any Map), .ppm (Portable
  Pixel Map), and others.

  Two heap-based buffer overflow flaws were found in the embedded JasPer
  library, which is used to provide support for Part 1 of the JPEG 2000 image
  compression standard in the jpeg2ktopam and pamtojpeg2k tools. An attacker
  could create a malicious JPEG 2000 compressed image file that could cause
  jpeg2ktopam to crash or, potentially, execute arbitrary code with the
  privileges of the user running jpeg2ktopam. These flaws do not affect
  pamtojpeg2k. (CVE-2011-4516, CVE-2011-4517)

  A stack-based buffer overflow flaw was found in the way the xpmtoppm tool
  processed X PixMap (XPM) image files. An attacker could create a malicious
  XPM file that would cause xpmtoppm to crash or, potentially, execute
  arbitrary code with the privileges of the user running xpmtoppm.
  (CVE-2009-4274)

  Red Hat would like to thank Jonathan Foote of the CERT Coordination Center
  for reporting the CVE-2011-4516 and CVE-2011-4517 issues.

  All users of netpbm are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.35.58~8.el5_7.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-debuginfo", rpm:"netpbm-debuginfo~10.35.58~8.el5_7.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-devel", rpm:"netpbm-devel~10.35.58~8.el5_7.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-progs", rpm:"netpbm-progs~10.35.58~8.el5_7.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"netpbm", rpm:"netpbm~10.35.58~8.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-debuginfo", rpm:"netpbm-debuginfo~10.35.58~8.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-devel", rpm:"netpbm-devel~10.35.58~8.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"netpbm-progs", rpm:"netpbm-progs~10.35.58~8.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
