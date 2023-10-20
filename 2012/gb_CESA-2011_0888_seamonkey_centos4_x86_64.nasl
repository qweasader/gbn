# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-August/017684.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881327");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:24:05 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363",
                "CVE-2011-2364", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373",
                "CVE-2011-2374", "CVE-2011-2375", "CVE-2011-2376", "CVE-2011-2377");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0888");
  script_name("CentOS Update for seamonkey CESA-2011:0888 centos4 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"seamonkey on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"SeaMonkey is an open source web browser, email and newsgroup client, IRC
  chat client, and HTML editor.

  A flaw was found in the way SeaMonkey handled malformed JPEG images. A
  website containing a malicious JPEG image could cause SeaMonkey to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running SeaMonkey. (CVE-2011-2377)

  Multiple dangling pointer flaws were found in SeaMonkey. A web page
  containing malicious content could cause SeaMonkey to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  SeaMonkey. (CVE-2011-0083, CVE-2011-0085, CVE-2011-2363)

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause SeaMonkey to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  SeaMonkey. (CVE-2011-2364, CVE-2011-2365, CVE-2011-2374, CVE-2011-2375,
  CVE-2011-2376)

  An integer overflow flaw was found in the way SeaMonkey handled JavaScript
  Array objects. A website containing malicious JavaScript could cause
  SeaMonkey to execute that JavaScript with the privileges of the user
  running SeaMonkey. (CVE-2011-2371)

  A use-after-free flaw was found in the way SeaMonkey handled malformed
  JavaScript. A website containing malicious JavaScript could cause SeaMonkey
  to execute that JavaScript with the privileges of the user running
  SeaMonkey. (CVE-2011-2373)

  It was found that SeaMonkey could treat two separate cookies as
  interchangeable if both were for the same domain name but one of those
  domain names had a trailing '.' character. This violates the same-origin
  policy and could possibly lead to data being leaked to the wrong domain.
  (CVE-2011-2362)

  All SeaMonkey users should upgrade to these updated packages, which correct
  these issues. After installing the update, SeaMonkey must be restarted for
  the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.9~71.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-chat", rpm:"seamonkey-chat~1.0.9~71.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-devel", rpm:"seamonkey-devel~1.0.9~71.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.0.9~71.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-js-debugger", rpm:"seamonkey-js-debugger~1.0.9~71.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.0.9~71.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
