# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870615");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:34:16 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-1429");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_xref(name:"RHSA", value:"2011:0959-01");
  script_name("RedHat Update for mutt RHSA-2011:0959-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"mutt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mutt is a text-mode mail user agent.

  A flaw was found in the way Mutt verified SSL certificates. When a server
  presented an SSL certificate chain, Mutt could ignore a server hostname
  check failure. A remote attacker able to get a certificate from a trusted
  Certificate Authority could use this flaw to trick Mutt into accepting a
  certificate issued for a different hostname, and perform man-in-the-middle
  attacks against Mutt's SSL connections. (CVE-2011-1429)

  All Mutt users should upgrade to this updated package, which contains a
  backported patch to correct this issue. All running instances of Mutt must
  be restarted for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.20~2.20091214hg736b6a.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mutt-debuginfo", rpm:"mutt-debuginfo~1.5.20~2.20091214hg736b6a.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
