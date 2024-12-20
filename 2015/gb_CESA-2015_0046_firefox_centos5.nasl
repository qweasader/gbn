# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882091");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-23 12:56:22 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-8634", "CVE-2014-8638", "CVE-2014-8639", "CVE-2014-8641");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for firefox CESA-2015:0046 centos5");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2014-8634, CVE-2014-8639, CVE-2014-8641)

It was found that the Beacon interface implementation in Firefox did not
follow the Cross-Origin Resource Sharing (CORS) specification. A web page
containing malicious content could allow a remote attacker to conduct a
Cross-Site Request Forgery (XSRF) attack. (CVE-2014-8638)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, Patrick McManus, Muneaki Nishimura,
Xiaofeng Zheng, and Mitchell Harper as the original reporters of these
issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Firefox 31.4.0 ESR. You can find a link to the Mozilla
advisories in the References section of this erratum.

This update also fixes the following bug:

  * The default dictionary for Firefox's spell checker is now correctly set
to the system's locale language. (BZ#643954, BZ#1150572)

All Firefox users should upgrade to these updated packages, which contain
Firefox version 31.4.0 ESR, which corrects these issues. After installing
the update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"affected", value:"firefox on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0046");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-January/020877.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~31.4.0~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}