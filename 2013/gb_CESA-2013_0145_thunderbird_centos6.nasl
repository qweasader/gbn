# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019049.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881554");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-11 16:44:17 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2013-0744", "CVE-2013-0746", "CVE-2013-0748", "CVE-2013-0750",
                "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0758", "CVE-2013-0759",
                "CVE-2013-0762", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0769");
  script_xref(name:"CESA", value:"2013:0145");
  script_name("CentOS Update for thunderbird CESA-2013:0145 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"thunderbird on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2013-0744,
  CVE-2013-0746, CVE-2013-0750, CVE-2013-0753, CVE-2013-0754, CVE-2013-0762,
  CVE-2013-0766, CVE-2013-0767, CVE-2013-0769)

  A flaw was found in the way Chrome Object Wrappers were implemented.
  Malicious content could be used to cause Thunderbird to execute arbitrary
  code via plug-ins installed in Thunderbird. (CVE-2013-0758)

  A flaw in the way Thunderbird displayed URL values could allow malicious
  content or a user to perform a phishing attack. (CVE-2013-0759)

  An information disclosure flaw was found in the way certain JavaScript
  functions were implemented in Thunderbird. An attacker could use this flaw
  to bypass Address Space Layout Randomization (ASLR) and other security
  restrictions. (CVE-2013-0748)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Atte Kettunen, Boris Zbarsky, pa_kt, regenrecht,
  Abhishek Arya, Christoph Diehl, Christian Holler, Mats Palmgren, Chiaki
  Ishikawa, Mariusz Mlynski, Masato Kinugawa, and Jesse Ruderman as the
  original reporters of these issues.

  Note: All issues except CVE-2013-0744, CVE-2013-0753, and CVE-2013-0754
  cannot be exploited by a specially-crafted HTML mail message as JavaScript
  is disabled by default for mail messages. They could be exploited another
  way in Thunderbird, for example, when viewing the full remote content of an
  RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 10.0.12 ESR, which corrects these issues.
  After installing the update, Thunderbird must be restarted for the changes
  to take effect.");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.12~3.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
