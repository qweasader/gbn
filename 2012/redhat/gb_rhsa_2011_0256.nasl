# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-February/msg00012.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870696");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-05 19:35:09 +0530 (Tue, 05 Jun 2012)");
  script_cve_id("CVE-2011-0413");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name:"RHSA", value:"2011:0256-01");
  script_name("RedHat Update for dhcp RHSA-2011:0256-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"dhcp on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The Dynamic Host Configuration Protocol (DHCP) is a protocol that allows
  individual devices on an IP network to get their own network configuration
  information, including an IP address, a subnet mask, and a broadcast
  address. DHCPv6 is the DHCP protocol version for IPv6 networks.

  A flaw was found in the way the dhcpd daemon processed certain DHCPv6
  messages for addresses that had previously been declined and marked as
  abandoned internally. If a remote attacker sent such messages to dhcpd, it
  could cause dhcpd to crash due to an assertion failure if it was running as
  a DHCPv6 server. (CVE-2011-0413)

  Red Hat would like to thank Internet Systems Consortium for reporting this
  issue.

  Users running dhcpd as a DHCPv6 server should upgrade to these updated
  packages, which contain a backported patch to correct this issue. After
  installing this update, all DHCP servers will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"dhclient", rpm:"dhclient~4.1.1~12.P1.el6_0.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.1.1~12.P1.el6_0.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp-debuginfo", rpm:"dhcp-debuginfo~4.1.1~12.P1.el6_0.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
