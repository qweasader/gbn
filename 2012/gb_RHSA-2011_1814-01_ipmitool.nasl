# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00036.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870715");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-09 10:52:46 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-4339");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name:"RHSA", value:"2011:1814-01");
  script_name("RedHat Update for ipmitool RHSA-2011:1814-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipmitool'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"ipmitool on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The ipmitool package contains a command line utility for interfacing with
  devices that support the Intelligent Platform Management Interface (IPMI)
  specification. IPMI is an open standard for machine health, inventory, and
  remote power control.

  It was discovered that the IPMI event daemon (ipmievd) created its process
  ID (PID) file with world-writable permissions. A local user could use this
  flaw to make the ipmievd init script kill an arbitrary process when the
  ipmievd daemon is stopped or restarted. (CVE-2011-4339)

  All users of ipmitool are advised to upgrade to this updated package, which
  contains a backported patch to correct this issue. After installing this
  update, the IPMI event daemon (ipmievd) will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"ipmitool", rpm:"ipmitool~1.8.11~12.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipmitool-debuginfo", rpm:"ipmitool-debuginfo~1.8.11~12.el6_2.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
