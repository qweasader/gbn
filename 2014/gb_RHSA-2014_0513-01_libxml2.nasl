# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871166");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-26 16:05:50 +0530 (Mon, 26 May 2014)");
  script_cve_id("CVE-2013-2877", "CVE-2014-0191");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for libxml2 RHSA-2014:0513-01");


  script_tag(name:"affected", value:"libxml2 on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The libxml2 library is a development toolbox providing the implementation
of various XML standards.

It was discovered that libxml2 loaded external parameter entities even when
entity substitution was disabled. A remote attacker able to provide a
specially crafted XML file to an application linked against libxml2 could
use this flaw to conduct XML External Entity (XXE) attacks, possibly
resulting in a denial of service or an information leak on the system.
(CVE-2014-0191)

An out-of-bounds read flaw was found in the way libxml2 detected the end of
an XML file. A remote attacker could provide a specially crafted XML file
that, when processed by an application linked against libxml2, could cause
the application to crash. (CVE-2013-2877)

The CVE-2014-0191 issue was discovered by Daniel P. Berrange of Red Hat.

All libxml2 users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The desktop must be
restarted (log out, then log back in) for this update to take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0513-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-May/msg00020.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.7.6~14.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-debuginfo", rpm:"libxml2-debuginfo~2.7.6~14.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.7.6~14.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.7.6~14.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}