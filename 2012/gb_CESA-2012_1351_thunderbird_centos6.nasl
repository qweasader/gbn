# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-October/018931.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881515");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-11 10:03:30 +0530 (Thu, 11 Oct 2012)");
  script_cve_id("CVE-2012-1956", "CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3988",
                "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993",
                "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180",
                "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184",
                "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2012:1351");
  script_name("CentOS Update for thunderbird CESA-2012:1351 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"thunderbird on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2012-3982,
  CVE-2012-3988, CVE-2012-3990, CVE-2012-3995, CVE-2012-4179, CVE-2012-4180,
  CVE-2012-4181, CVE-2012-4182, CVE-2012-4183, CVE-2012-4185, CVE-2012-4186,
  CVE-2012-4187, CVE-2012-4188)

  Two flaws in Thunderbird could allow malicious content to bypass intended
  restrictions, possibly leading to information disclosure, or Thunderbird
  executing arbitrary code. Note that the information disclosure issue could
  possibly be combined with other flaws to achieve arbitrary code execution.
  (CVE-2012-3986, CVE-2012-3991)

  Multiple flaws were found in the location object implementation in
  Thunderbird. Malicious content could be used to perform cross-site
  scripting attacks, script injection, or spoofing attacks. (CVE-2012-1956,
  CVE-2012-3992, CVE-2012-3994)

  Two flaws were found in the way Chrome Object Wrappers were implemented.
  Malicious content could be used to perform cross-site scripting attacks or
  cause Thunderbird to execute arbitrary code. (CVE-2012-3993, CVE-2012-4184)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Christian Holler, Jesse Ruderman, Soroush Dalili,
  miaubiz, Abhishek Arya, Atte Kettunen, Johnny Stenback, Alice White,
  moz_bug_r_a4, and Mariusz Mlynski as the original reporters of these
  issues.

  Note: None of the issues in this advisory can be exploited by a
  specially-crafted HTML mail message as JavaScript is disabled by default
  for mail messages. They could be exploited another way in Thunderbird, for
  example, when viewing the full remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 10.0.8 ESR, which corrects these issues. After
  installing the update, Thunderbird must be restarted for the changes to
  take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.8~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
