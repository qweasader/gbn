# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-July/msg00010.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870786");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-16 11:52:18 +0530 (Mon, 16 Jul 2012)");
  script_cve_id("CVE-2009-5030", "CVE-2012-3358");
  script_xref(name:"RHSA", value:"2012:1068-01");
  script_name("RedHat Update for openjpeg RHSA-2012:1068-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"openjpeg on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
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
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"openjpeg-debuginfo", rpm:"openjpeg-debuginfo~1.3~8.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openjpeg-libs", rpm:"openjpeg-libs~1.3~8.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
