# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871662");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-22 05:37:08 +0200 (Thu, 22 Sep 2016)");
  script_cve_id("CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5261", "CVE-2016-5270",
                "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277",
                "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-12 01:29:00 +0000 (Tue, 12 Jun 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for firefox RHSA-2016:1912-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.
This update upgrades Firefox to version 45.4.0 ESR.
Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2016-5257, CVE-2016-5278, CVE-2016-5270, CVE-2016-5272,
CVE-2016-5274, CVE-2016-5276, CVE-2016-5277, CVE-2016-5280, CVE-2016-5281,
CVE-2016-5284, CVE-2016-5250, CVE-2016-5261)
Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Samuel GroB, Brian Carpenter, Mei Wang, Ryan Duff,
Catalin Dumitru, Mozilla developers, Christoph Diehl, Andrew McCreight, Dan
Minor, Byron Campen, Jon Coppeard, Steve Fink, Tyson Smith, Philipp,
Carsten Book, Abhishek Arya, Atte Kettunen, and Nils as the original
reporters.");
  script_tag(name:"affected", value:"firefox on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:1912-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-September/msg00026.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6|5)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.4.0~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~45.4.0~1.el7_2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.4.0~1.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~45.4.0~1.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~45.4.0~1.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~45.4.0~1.el5_11", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
