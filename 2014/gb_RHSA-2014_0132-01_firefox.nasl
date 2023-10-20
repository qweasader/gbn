# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871118");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-11 10:46:36 +0530 (Tue, 11 Feb 2014)");
  script_cve_id("CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482",
                "CVE-2014-1486", "CVE-2014-1487");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-07 19:37:00 +0000 (Fri, 07 Aug 2020)");
  script_name("RedHat Update for firefox RHSA-2014:0132-01");


  script_tag(name:"affected", value:"firefox on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2014-1477, CVE-2014-1482, CVE-2014-1486)

A flaw was found in the way Firefox handled error messages related to web
workers. An attacker could use this flaw to bypass the same-origin policy,
which could lead to cross-site scripting (XSS) attacks, or could
potentially be used to gather authentication tokens and other data from
third-party websites. (CVE-2014-1487)

A flaw was found in the implementation of System Only Wrappers (SOW).
An attacker could use this flaw to crash Firefox. When combined with other
vulnerabilities, this flaw could have additional security implications.
(CVE-2014-1479)

It was found that the Firefox JavaScript engine incorrectly handled window
objects. A remote attacker could use this flaw to bypass certain security
checks and possibly execute arbitrary code. (CVE-2014-1481)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, Terrence Cole, Jesse Ruderman, Gary
Kwong, Eric Rescorla, Jonathan Kew, Dan Gohman, Ryan VanderMeulen, Sotaro
Ikeda, Cody Crews, Fredrik 'Flonka' Lonnqvist, Arthur Gerkis, Masato
Kinugawa, and Boris Zbarsky as the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 24.3.0 ESR. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 24.3.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0132-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-February/msg00003.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(6|5)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~24.3.0~2.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~24.3.0~2.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~24.3.0~2.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~24.3.0~2.el5_10", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
