# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882228");
  script_version("2023-07-11T05:06:07+0000");
  script_cve_id("CVE-2015-2724", "CVE-2015-2725", "CVE-2015-2731", "CVE-2015-2734",
                "CVE-2015-2735", "CVE-2015-2736", "CVE-2015-2737", "CVE-2015-2738",
                "CVE-2015-2739", "CVE-2015-2740", "CVE-2015-2741");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-21 06:36:22 +0200 (Tue, 21 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for thunderbird CESA-2015:1455 centos6");
  script_tag(name:"summary", value:"Check the version of thunderbird");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2015-2724, CVE-2015-2725, CVE-2015-2731, CVE-2015-2734,
CVE-2015-2735, CVE-2015-2736, CVE-2015-2737, CVE-2015-2738, CVE-2015-2739,
CVE-2015-2740)

It was found that Thunderbird skipped key-pinning checks when handling an
error that could be overridden by the user (for example an expired
certificate error). This flaw allowed a user to override a pinned
certificate, which is an action the user should not be able to perform.
(CVE-2015-2741)

Note: All of the above issues cannot be exploited by a specially crafted
HTML mail message as JavaScript is disabled by default for mail messages.
They could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bob Clary, Christian Holler, Bobby Holley, Andrew
McCreight, Herre, Ronald Crane, and David Keeler as the original reporters
of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 31.8. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 31.8, which corrects these issues.
After installing the update, Thunderbird must be restarted for the changes
to take effect.");
  script_tag(name:"affected", value:"thunderbird on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1455");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-July/021251.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~31.8.0~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
