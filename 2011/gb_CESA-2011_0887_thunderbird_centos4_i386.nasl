# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-August/017681.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880952");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0887");
  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2377");
  script_name("CentOS Update for thunderbird CESA-2011:0887 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"thunderbird on CentOS 4");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  A flaw was found in the way Thunderbird handled malformed JPEG images. An
  HTML mail message containing a malicious JPEG image could cause Thunderbird
  to crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2011-2377)

  Multiple dangling pointer flaws were found in Thunderbird. Malicious HTML
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2011-0083,
  CVE-2011-0085, CVE-2011-2363)

  Several flaws were found in the processing of malformed HTML content.
  Malicious HTML content could cause Thunderbird to crash or, potentially,
  execute arbitrary code with the privileges of the user running Thunderbird.
  (CVE-2011-2364, CVE-2011-2365, CVE-2011-2374, CVE-2011-2375, CVE-2011-2376)

  An integer overflow flaw was found in the way Thunderbird handled
  JavaScript Array objects. Malicious content could cause Thunderbird to
  execute JavaScript with the privileges of the user running Thunderbird.
  (CVE-2011-2371)

  A use-after-free flaw was found in the way Thunderbird handled malformed
  JavaScript. Malicious content could cause Thunderbird to execute JavaScript
  with the privileges of the user running Thunderbird. (CVE-2011-2373)

  It was found that Thunderbird could treat two separate cookies (for web
  content) as interchangeable if both were for the same domain name but one
  of those domain names had a trailing '.' character. This violates the
  same-origin policy and could possibly lead to data being leaked to the
  wrong domain. (CVE-2011-2362)

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~1.5.0.12~39.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
