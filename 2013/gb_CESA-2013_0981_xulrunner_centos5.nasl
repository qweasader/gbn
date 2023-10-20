# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881760");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-06-27 10:00:16 +0530 (Thu, 27 Jun 2013)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686",
                "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693",
                "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for xulrunner CESA-2013:0981 centos5");

  script_xref(name:"CESA", value:"2013:0981");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-June/019816.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xulrunner'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"xulrunner on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2013-1682, CVE-2013-1684, CVE-2013-1685, CVE-2013-1686,
  CVE-2013-1687, CVE-2013-1690)

  It was found that Firefox allowed data to be sent in the body of
  XMLHttpRequest (XHR) HEAD requests. In some cases this could allow
  attackers to conduct Cross-Site Request Forgery (CSRF) attacks.
  (CVE-2013-1692)

  Timing differences in the way Firefox processed SVG image files could
  allow an attacker to read data across domains, potentially leading to
  information disclosure. (CVE-2013-1693)

  Two flaws were found in the way Firefox implemented some of its internal
  structures (called wrappers). An attacker could use these flaws to bypass
  some restrictions placed on them. This could lead to unexpected behavior or
  a potentially exploitable crash. (CVE-2013-1694, CVE-2013-1697)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Gary Kwong, Jesse Ruderman, Andrew McCreight,
  Abhishek Arya, Mariusz Mlynski, Nils, Johnathan Kuskos, Paul Stone, Boris
  Zbarsky, and moz_bug_r_a4 as the original reporters of these issues.

  For technical details regarding these flaws, refer to the Mozilla
  security advisories for Firefox 17.0.7 ESR. You can find a link to the
  Mozilla advisories in the References section of this erratum.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 17.0.7 ESR, which corrects these issues. After installing
  the update, Firefox must be restarted for the changes to take effect.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.7~1.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.7~1.el5_9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
