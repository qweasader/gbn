# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-March/018500.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881166");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:28:45 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457",
                "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461",
                "CVE-2012-0462", "CVE-2012-0464");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2012:0388");
  script_name("CentOS Update for thunderbird CESA-2012:0388 centos6");

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
  code with the privileges of the user running Thunderbird. (CVE-2012-0461,
  CVE-2012-0462, CVE-2012-0464)

  Two flaws were found in the way Thunderbird parsed certain Scalable Vector
  Graphics (SVG) image files. An HTML mail message containing a malicious SVG
  image file could cause an information leak, or cause Thunderbird to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running Thunderbird. (CVE-2012-0456, CVE-2012-0457)

  A flaw could allow malicious content to bypass intended restrictions,
  possibly leading to a cross-site scripting (XSS) attack if a user were
  tricked into dropping a 'javascript:' link onto a frame. (CVE-2012-0455)

  It was found that the home page could be set to a 'javascript:' link. If a
  user were tricked into setting such a home page by dragging a link to the
  home button, it could cause Firefox to repeatedly crash, eventually leading
  to arbitrary code execution with the privileges of the user running
  Firefox. A similar flaw was found and fixed in Thunderbird. (CVE-2012-0458)

  A flaw was found in the way Thunderbird parsed certain, remote content
  containing 'cssText'. Malicious, remote content could cause Thunderbird to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2012-0459)

  It was found that by using the DOM fullscreen API, untrusted content could
  bypass the mozRequestFullscreen security protections. Malicious content
  could exploit this API flaw to cause user interface spoofing.
  (CVE-2012-0460)

  A flaw was found in the way Thunderbird handled content with multiple
  Content Security Policy (CSP) headers. This could lead to a cross-site
  scripting attack if used in conjunction with a website that has a header
  injection flaw. (CVE-2012-0451)

  Note: All issues except CVE-2012-0456 and CVE-2012-0457 cannot be exploited
  by a specially-crafted HTML mail message as JavaScript is disabled by
  default for mail messages. It could be exploited another way in
  Thunderbird, for example, when viewing the full remote content of an RSS
  feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 10.0.3 ESR, which corrects these issues. After
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.3~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
