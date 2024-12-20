# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882232");
  script_version("2023-07-11T05:06:07+0000");
  script_cve_id("CVE-2015-3213");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-10 12:58:28 +0530 (Mon, 10 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for clutter CESA-2015:1510 centos7");
  script_tag(name:"summary", value:"Check the version of clutter");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Clutter is a library for creating fast, visually rich, graphical user
interfaces. Clutter is used for rendering the GNOME desktop environment.

A flaw was found in the way clutter processed certain mouse and touch
gestures. An attacker could use this flaw to bypass the screen lock.
(CVE-2015-3213)

All clutter users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, all applications using clutter must be restarted for the update to
take effect.");
  script_tag(name:"affected", value:"clutter on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1510");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-July/021267.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"clutter", rpm:"clutter~1.14.4~12.el7_1.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clutter-devel", rpm:"clutter-devel~1.14.4~12.el7_1.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clutter-doc", rpm:"clutter-doc~1.14.4~12.el7_1.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
