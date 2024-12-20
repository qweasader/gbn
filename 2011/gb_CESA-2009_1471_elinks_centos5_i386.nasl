# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016224.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880805");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name:"CESA", value:"2009:1471");
  script_cve_id("CVE-2007-2027", "CVE-2008-7224");
  script_name("CentOS Update for elinks CESA-2009:1471 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elinks'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"elinks on CentOS 5");
  script_tag(name:"insight", value:"ELinks is a text-based Web browser. ELinks does not display any images, but
  it does support frames, tables, and most other HTML tags.

  An off-by-one buffer overflow flaw was discovered in the way ELinks handled
  its internal cache of string representations for HTML special entities. A
  remote attacker could use this flaw to create a specially-crafted HTML file
  that would cause ELinks to crash or, possibly, execute arbitrary code when
  rendered. (CVE-2008-7224)

  It was discovered that ELinks tried to load translation files using
  relative paths. A local attacker able to trick a victim into running ELinks
  in a folder containing specially-crafted translation files could use this
  flaw to confuse the victim via incorrect translations, or cause ELinks to
  crash and possibly execute arbitrary code via embedded formatting sequences
  in translated messages. (CVE-2007-2027)

  All ELinks users are advised to upgrade to this updated package, which
  contains backported patches to resolve these issues.");
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

  if ((res = isrpmvuln(pkg:"elinks", rpm:"elinks~0.11.1~6.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
