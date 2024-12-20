# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-July/016034.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880710");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1154");
  script_cve_id("CVE-2009-0692", "CVE-2009-1893");
  script_name("CentOS Update for dhclient CESA-2009:1154 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhclient'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"dhclient on CentOS 3");
  script_tag(name:"insight", value:"The Dynamic Host Configuration Protocol (DHCP) is a protocol that allows
  individual devices on an IP network to get their own network configuration
  information, including an IP address, a subnet mask, and a broadcast
  address.

  The Mandriva Linux Engineering Team discovered a stack-based buffer
  overflow flaw in the ISC DHCP client. If the DHCP client were to receive a
  malicious DHCP response, it could crash or execute arbitrary code with the
  permissions of the client (root). (CVE-2009-0692)

  An insecure temporary file use flaw was discovered in the DHCP daemon's
  init script ('/etc/init.d/dhcpd'). A local attacker could use this flaw to
  overwrite an arbitrary file with the output of the 'dhcpd -t' command via
  a symbolic link attack, if a system administrator executed the DHCP init
  script with the 'configtest', &'restart', or 'reload' option.
  (CVE-2009-1893)

  Users of DHCP should upgrade to these updated packages, which contain
  backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"dhclient", rpm:"dhclient~3.0.1~10.2_EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~3.0.1~10.2_EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dhcp-devel", rpm:"dhcp-devel~3.0.1~10.2_EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
