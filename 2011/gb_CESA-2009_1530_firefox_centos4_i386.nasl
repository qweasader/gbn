# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016206.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880839");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1530");
  script_cve_id("CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3274", "CVE-2009-0689",
                "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376",
                "CVE-2009-3380", "CVE-2009-3382");
  script_name("CentOS Update for firefox CESA-2009:1530 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"firefox on CentOS 4");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox. nspr provides the Netscape
  Portable Runtime (NSPR).

  A flaw was found in the way Firefox handles form history. A malicious web
  page could steal saved form data by synthesizing input events, causing the
  browser to auto-fill form fields (which could then be read by an attacker).
  (CVE-2009-3370)

  A flaw was found in the way Firefox creates temporary file names for
  downloaded files. If a local attacker knows the name of a file Firefox is
  going to download, they can replace the contents of that file with
  arbitrary contents. (CVE-2009-3274)

  A flaw was found in the Firefox Proxy Auto-Configuration (PAC) file
  processor. If Firefox loads a malicious PAC file, it could crash Firefox
  or, potentially, execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2009-3372)

  A heap-based buffer overflow flaw was found in the Firefox GIF image
  processor. A malicious GIF image could crash Firefox or, potentially,
  execute arbitrary code with the privileges of the user running Firefox.
  (CVE-2009-3373)

  A heap-based buffer overflow flaw was found in the Firefox string to
  floating point conversion routines. A web page containing malicious
  JavaScript could crash Firefox or, potentially, execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2009-1563)

  A flaw was found in the way Firefox handles text selection. A malicious
  website may be able to read highlighted text in a different domain (e.g.
  another website the user is viewing), bypassing the same-origin policy.
  (CVE-2009-3375)

  A flaw was found in the way Firefox displays a right-to-left override
  character when downloading a file. In these cases, the name displayed in
  the title bar differs from the name displayed in the dialog body. An
  attacker could use this flaw to trick a user into downloading a file that
  has a file name or extension that differs from what the user expected.
  (CVE-2009-3376)

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2009-3374, CVE-2009-3380, CVE-2009-3382)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.15. You can find a link to the Mozilla
  advisories in the References section of this errata.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.15, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.15~3.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.7.6~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.7.6~1.el4_8", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
