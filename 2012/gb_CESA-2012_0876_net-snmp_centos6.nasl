# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018717.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881163");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:27:19 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-2141");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2012:0876");
  script_name("CentOS Update for net-snmp CESA-2012:0876 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'net-snmp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"net-snmp on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The net-snmp packages provide various libraries and tools for the Simple
  Network Management Protocol (SNMP), including an SNMP library, an
  extensible agent, tools for requesting or setting information from SNMP
  agents, tools for generating and handling SNMP traps, a version of the
  netstat command which uses SNMP, and a Tk/Perl Management Information Base
  (MIB) browser.

  An array index error, leading to an out-of-bounds buffer read flaw, was
  found in the way the net-snmp agent looked up entries in the extension
  table. A remote attacker with read privileges to a Management Information
  Base (MIB) subtree handled by the 'extend' directive (in
  '/etc/snmp/snmpd.conf') could use this flaw to crash snmpd via a crafted
  SNMP GET request. (CVE-2012-2141)

  These updated net-snmp packages also include numerous bug fixes. Space
  precludes documenting all of these changes in this advisory. Users are
  directed to the Red Hat Enterprise Linux 6.3 Technical Notes for
  information on the most significant of these changes.

  All users of net-snmp are advised to upgrade to these updated packages,
  which contain backported patches to resolve these issues. After installing
  the update, the snmpd and snmptrapd daemons will be restarted
  automatically.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.5~41.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-devel", rpm:"net-snmp-devel~5.5~41.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.5~41.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-perl", rpm:"net-snmp-perl~5.5~41.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-python", rpm:"net-snmp-python~5.5~41.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"net-snmp-utils", rpm:"net-snmp-utils~5.5~41.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
