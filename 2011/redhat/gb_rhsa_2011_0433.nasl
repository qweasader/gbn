# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-April/msg00010.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870421");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-04-19 07:58:39 +0200 (Tue, 19 Apr 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:0433-01");
  script_cve_id("CVE-2011-0465");
  script_name("RedHat Update for xorg-x11-server-utils RHSA-2011:0433-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"xorg-x11-server-utils on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The xorg-x11-server-utils package contains a collection of utilities used
  to modify and query the runtime configuration of the X.Org server. X.Org is
  an open source implementation of the X Window System.

  A flaw was found in the X.Org X server resource database utility, xrdb.
  Certain variables were not properly sanitized during the launch of a user's
  graphical session, which could possibly allow a remote attacker to execute
  arbitrary code with root privileges, if they were able to make the display
  manager execute xrdb with a specially-crafted X client hostname. For
  example, by configuring the hostname on the target system via a crafted
  DHCP reply, or by using the X Display Manager Control Protocol (XDMCP) to
  connect to that system from a host that has a special DNS name.
  (CVE-2011-0465)

  Red Hat would like to thank Matthieu Herrb for reporting this issue.
  Upstream acknowledges Sebastian Krahmer of the SuSE Security Team as the
  original reporter.

  Users of xorg-x11-server-utils should upgrade to this updated package,
  which contains a backported patch to resolve this issue. All running X.Org
  server instances must be restarted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"xorg-x11-server-utils", rpm:"xorg-x11-server-utils~7.1~5.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-utils-debuginfo", rpm:"xorg-x11-server-utils-debuginfo~7.1~5.el5_6.1", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
