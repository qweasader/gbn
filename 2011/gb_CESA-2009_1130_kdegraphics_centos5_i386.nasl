# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-June/016009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880857");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1130");
  script_cve_id("CVE-2009-0945", "CVE-2009-1709");
  script_name("CentOS Update for kdegraphics CESA-2009:1130 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdegraphics'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kdegraphics on CentOS 5");
  script_tag(name:"insight", value:"The kdegraphics packages contain applications for the K Desktop Environment
  (KDE). Scalable Vector Graphics (SVG) is an XML-based language to describe
  vector images. KSVG is a framework aimed at implementing the latest W3C SVG
  specifications.

  A use-after-free flaw was found in the KDE KSVG animation element
  implementation. A remote attacker could create a specially-crafted SVG
  image, which once opened by an unsuspecting user, could cause a denial of
  service (Konqueror crash) or, potentially, execute arbitrary code with the
  privileges of the user running Konqueror. (CVE-2009-1709)

  A NULL pointer dereference flaw was found in the KDE, KSVG SVGList
  interface implementation. A remote attacker could create a
  specially-crafted SVG image, which once opened by an unsuspecting user,
  would cause memory corruption, leading to a denial of service (Konqueror
  crash). (CVE-2009-0945)

  All users of kdegraphics should upgrade to these updated packages, which
  contain backported patches to correct these issues. The desktop must be
  restarted (log out, then log back in) for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.5.4~13.el5_3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-devel", rpm:"kdegraphics-devel~3.5.4~13.el5_3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
