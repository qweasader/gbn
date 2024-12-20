# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-October/017064.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880621");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2010:0720");
  script_cve_id("CVE-2007-6720", "CVE-2009-3995", "CVE-2009-3996");
  script_name("CentOS Update for mikmod CESA-2010:0720 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mikmod'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"mikmod on CentOS 5");
  script_tag(name:"insight", value:"MikMod is a MOD music file player for Linux, UNIX, and similar operating
  systems. It supports various file formats including MOD, STM, S3M, MTM, XM,
  ULT, and IT.

  Multiple input validation flaws, resulting in buffer overflows, were
  discovered in MikMod. Specially-crafted music files in various formats
  could, when played, cause an application using the MikMod library to crash
  or, potentially, execute arbitrary code. (CVE-2009-3995, CVE-2009-3996,
  CVE-2007-6720)

  All MikMod users should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running applications using
  the MikMod library must be restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  if ((res = isrpmvuln(pkg:"mikmod", rpm:"mikmod~3.1.6~39.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mikmod-devel", rpm:"mikmod-devel~3.1.6~39.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
