# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882218");
  script_version("2023-07-11T05:06:07+0000");
  script_cve_id("CVE-2015-2722", "CVE-2015-2724", "CVE-2015-2725",
                "CVE-2015-2727", "CVE-2015-2728", "CVE-2015-2729",
                "CVE-2015-2731", "CVE-2015-2733", "CVE-2015-2734",
                "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737",
                "CVE-2015-2738", "CVE-2015-2739", "CVE-2015-2740",
                "CVE-2015-2741", "CVE-2015-2743");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-07 06:43:54 +0200 (Tue, 07 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2015:1207 centos7");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source
  web browser. XULRunner provides the XUL
Runtime environment for Mozilla Firefox.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2015-2724, CVE-2015-2725, CVE-2015-2722, CVE-2015-2727,
CVE-2015-2728, CVE-2015-2729, CVE-2015-2731, CVE-2015-2733, CVE-2015-2734,
CVE-2015-2735, CVE-2015-2736, CVE-2015-2737, CVE-2015-2738, CVE-2015-2739,
CVE-2015-2740)

It was found that Firefox skipped key-pinning checks when handling an error
that could be overridden by the user (for example an expired certificate
error). This flaw allowed a user to override a pinned certificate, which is
an action the user should not be able to perform. (CVE-2015-2741)

A flaw was discovered in Mozilla's PDF.js PDF file viewer. When combined
with another vulnerability, it could allow execution of arbitrary code with
the privileges of the user running Firefox. (CVE-2015-2743)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bob Clary, Christian Holler, Bobby Holley, Andrew
McCreight, Terrence Cole, Steve Fink, Mats Palmgren, Wes Kocher, Andreas
Pehrson, Jann Horn, Paul Bandha, Holger Fuhrmannek, Herre, Looben Yan,
Ronald Crane, and Jonas Jenwald as the original reporters of these issues.

All Firefox users should upgrade to these updated packages, which contain
Firefox version 38.1 ESR, which corrects these issues. After installing the
update, Firefox must be restarted for the changes to take effect.");
  script_tag(name:"affected", value:"firefox on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1207");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-July/021234.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~38.1.0~1.el7.centos", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
