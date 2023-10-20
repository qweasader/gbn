# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00064.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54418");
  script_oid("1.3.6.1.4.1.25623.1.0.870915");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-22 10:01:20 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-3386");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2013:0526-02");
  script_name("RedHat Update for automake RHSA-2013:0526-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'automake'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"automake on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Automake is a tool for automatically generating Makefile.in files compliant
  with the GNU Coding Standards.

  It was found that the distcheck rule in Automake-generated Makefiles made a
  directory world-writable when preparing source archives. If a malicious,
  local user could access this directory, they could execute arbitrary code
  with the privileges of the user running make distcheck. (CVE-2012-3386)

  Red Hat would like to thank Jim Meyering for reporting this issue. Upstream
  acknowledges Stefano Lattarini as the original reporter.

  Users of automake are advised to upgrade to this updated package, which
  corrects this issue.");
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

  if ((res = isrpmvuln(pkg:"automake", rpm:"automake~1.11.1~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
