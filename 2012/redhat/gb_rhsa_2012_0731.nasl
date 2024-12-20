# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00011.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870754");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-15 09:45:45 +0530 (Fri, 15 Jun 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2012-0876", "CVE-2012-1148");
  script_xref(name:"RHSA", value:"2012:0731-01");
  script_name("RedHat Update for expat RHSA-2012:0731-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(6|5)");
  script_tag(name:"affected", value:"expat on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Expat is a C library written by James Clark for parsing XML documents.

  A denial of service flaw was found in the implementation of hash arrays in
  Expat. An attacker could use this flaw to make an application using Expat
  consume an excessive amount of CPU time by providing a specially-crafted
  XML file that triggers multiple hash function collisions. To mitigate
  this issue, randomization has been added to the hash function to reduce the
  chance of an attacker successfully causing intentional collisions.
  (CVE-2012-0876)

  A memory leak flaw was found in Expat. If an XML file processed by an
  application linked against Expat triggered a memory re-allocation failure,
  Expat failed to free the previously allocated memory. This could cause the
  application to exit unexpectedly or crash when all available memory is
  exhausted. (CVE-2012-1148)

  All Expat users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, applications using the Expat library must be restarted for the
  update to take effect.");
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

  if ((res = isrpmvuln(pkg:"expat", rpm:"expat~2.0.1~11.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"expat-debuginfo", rpm:"expat-debuginfo~2.0.1~11.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"expat-devel", rpm:"expat-devel~2.0.1~11.el6_2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"expat", rpm:"expat~1.95.8~11.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"expat-debuginfo", rpm:"expat-debuginfo~1.95.8~11.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"expat-devel", rpm:"expat-devel~1.95.8~11.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
