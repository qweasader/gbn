# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881899");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-17 13:12:30 +0530 (Mon, 17 Mar 2014)");
  script_cve_id("CVE-2014-0004");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for udisks CESA-2014:0293 centos6");

  script_tag(name:"affected", value:"udisks on CentOS 6");
  script_tag(name:"insight", value:"The udisks package provides a daemon, a D-Bus API, and command line
utilities for managing disks and storage devices.

A stack-based buffer overflow flaw was found in the way udisks handled
files with long path names. A malicious, local user could use this flaw to
create a specially crafted directory structure that, when processed by the
udisks daemon, could lead to arbitrary code execution with the privileges
of the udisks daemon (root). (CVE-2014-0004)

This issue was discovered by Florian Weimer of the Red Hat Product
Security Team.

All udisks users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0293");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-March/020200.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'udisks'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"udisks", rpm:"udisks~1.0.1~7.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udisks-devel", rpm:"udisks-devel~1.0.1~7.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udisks-devel-docs", rpm:"udisks-devel-docs~1.0.1~7.el6_5", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}