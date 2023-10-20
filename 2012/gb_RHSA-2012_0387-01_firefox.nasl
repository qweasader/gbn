# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-March/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870575");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-03-16 10:48:43 +0530 (Fri, 16 Mar 2012)");
  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457",
                "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461",
                "CVE-2012-0462", "CVE-2012-0464");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:0387-01");
  script_name("RedHat Update for firefox RHSA-2012:0387-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"firefox on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2012-0461, CVE-2012-0462, CVE-2012-0464)

  Two flaws were found in the way Firefox parsed certain Scalable Vector
  Graphics (SVG) image files. A web page containing a malicious SVG image
  file could cause an information leak, or cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2012-0456, CVE-2012-0457)

  A flaw could allow a malicious site to bypass intended restrictions,
  possibly leading to a cross-site scripting (XSS) attack if a user were
  tricked into dropping a 'javascript:' link onto a frame. (CVE-2012-0455)

  It was found that the home page could be set to a 'javascript:' link. If a
  user were tricked into setting such a home page by dragging a link to the
  home button, it could cause Firefox to repeatedly crash, eventually
  leading to arbitrary code execution with the privileges of the user
  running Firefox. (CVE-2012-0458)

  A flaw was found in the way Firefox parsed certain web content containing
  'cssText'. A web page containing malicious content could cause Firefox to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running Firefox. (CVE-2012-0459)

  It was found that by using the DOM fullscreen API, untrusted content could
  bypass the mozRequestFullscreen security protections. A web page containing
  malicious web content could exploit this API flaw to cause user interface
  spoofing. (CVE-2012-0460)

  A flaw was found in the way Firefox handled pages with multiple Content
  Security Policy (CSP) headers. This could lead to a cross-site scripting
  attack if used in conjunction with a website that has a header injection
  flaw. (CVE-2012-0451)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 10.0.3 ESR. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  This update also fixes the following bugs:

  * When using the Traditional Chinese locale (zh-TW), a segmentation fault
  sometimes occurred when closing Firefox. (BZ#729632)

  * The java-1.6.0-ibm-plugin and java-1.6.0-sun-pl ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.3~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~10.0.3~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~10.0.3~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~10.0.3~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~10.0.3~1.el5_8", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
