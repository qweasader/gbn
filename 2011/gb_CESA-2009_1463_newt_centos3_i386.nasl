# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016171.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880778");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:1463");
  script_cve_id("CVE-2009-2905");
  script_name("CentOS Update for newt CESA-2009:1463 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'newt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"newt on CentOS 3");
  script_tag(name:"insight", value:"Newt is a programming library for color text mode, widget-based user
  interfaces. Newt can be used to add stacked windows, entry widgets,
  checkboxes, radio buttons, labels, plain text fields, scrollbars, and so
  on, to text mode user interfaces.

  A heap-based buffer overflow flaw was found in the way newt processes
  content that is to be displayed in a text dialog box. A local attacker
  could issue a specially-crafted text dialog box display request (direct or
  via a custom application), leading to a denial of service (application
  crash) or, potentially, arbitrary code execution with the privileges of the
  user running the application using the newt library. (CVE-2009-2905)

  Users of newt should upgrade to these updated packages, which contain a
  backported patch to correct this issue. After installing the updated
  packages, all applications using the newt library must be restarted for the
  update to take effect.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"newt", rpm:"newt~0.51.5~2.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"newt-devel", rpm:"newt-devel~0.51.5~2.el3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
