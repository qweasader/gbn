# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-April/msg00024.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870587");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-04-26 10:35:00 +0530 (Thu, 26 Apr 2012)");
  script_cve_id("CVE-2011-3048");
  script_xref(name:"RHSA", value:"2012:0523-01");
  script_name("RedHat Update for libpng RHSA-2012:0523-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"libpng on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A heap-based buffer overflow flaw was found in the way libpng processed
  tEXt chunks in PNG image files. An attacker could create a
  specially-crafted PNG image file that, when opened, could cause an
  application using libpng to crash or, possibly, execute arbitrary code with
  the privileges of the user running the application. (CVE-2011-3048)

  Users of libpng should upgrade to these updated packages, which correct
  this issue. For Red Hat Enterprise Linux 5, they contain a backported
  patch. For Red Hat Enterprise Linux 6, they upgrade libpng to version
  1.2.49. All running applications using libpng must be restarted for the
  update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.10~17.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.2.10~17.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.10~17.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
