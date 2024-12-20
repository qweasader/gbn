# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018732.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881083");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:03:41 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-5030", "CVE-2012-3358");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2012:1068");
  script_name("CentOS Update for openjpeg CESA-2012:1068 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"openjpeg on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"OpenJPEG is an open source library for reading and writing image files in
  JPEG 2000 format.

  An input validation flaw, leading to a heap-based buffer overflow, was
  found in the way OpenJPEG handled the tile number and size in an image tile
  header. A remote attacker could provide a specially-crafted image file
  that, when decoded using an application linked against OpenJPEG, would
  cause the application to crash or, potentially, execute arbitrary code with
  the privileges of the user running the application. (CVE-2012-3358)

  OpenJPEG allocated insufficient memory when encoding JPEG 2000 files from
  input images that have certain color depths. A remote attacker could
  provide a specially-crafted image file that, when opened in an application
  linked against OpenJPEG (such as image_to_j2k), would cause the application
  to crash or, potentially, execute arbitrary code with the privileges of the
  user running the application. (CVE-2009-5030)

  Users of OpenJPEG should upgrade to these updated packages, which contain
  patches to correct these issues. All running applications using OpenJPEG
  must be restarted for the update to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"openjpeg", rpm:"openjpeg~1.3~8.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg-devel", rpm:"openjpeg-devel~1.3~8.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg-libs", rpm:"openjpeg-libs~1.3~8.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
