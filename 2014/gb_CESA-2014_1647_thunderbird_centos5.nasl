# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882059");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-10-16 05:59:48 +0200 (Thu, 16 Oct 2014)");
  script_cve_id("CVE-2014-1574", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1581");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for thunderbird CESA-2014:1647 centos5");

  script_tag(name:"summary", value:"Check the version of thunderbird");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail
and newsgroup client.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2014-1574, CVE-2014-1578, CVE-2014-1581, CVE-2014-1577)

Note: All of the above issues cannot be exploited by a specially crafted
HTML mail message as JavaScript is disabled by default for mail messages.
They could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bobby Holley, Christian Holler, David Bolter, Byron
Campen Jon Coppeard, Holger Fuhrmannek, Abhishek Arya, and regenrecht as
the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 31.2.0. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 31.2.0, which corrects these issues.
After installing the update, Thunderbird must be restarted for the changes
to take effect.");
  script_tag(name:"affected", value:"thunderbird on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:1647");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-October/020692.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~31.2.0~2.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
