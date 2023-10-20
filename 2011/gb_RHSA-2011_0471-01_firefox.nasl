# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-April/msg00025.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870425");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-05 07:14:22 +0200 (Thu, 05 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:0471-01");
  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");
  script_name("RedHat Update for firefox RHSA-2011:0471-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(5|4)");
  script_tag(name:"affected", value:"firefox on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could possibly lead to arbitrary code
  execution with the privileges of the user running Firefox. (CVE-2011-0080,
  CVE-2011-0081)

  An arbitrary memory write flaw was found in the way Firefox handled
  out-of-memory conditions. If all memory was consumed when a user visited a
  malicious web page, it could possibly lead to arbitrary code execution
  with the privileges of the user running Firefox. (CVE-2011-0078)

  An integer overflow flaw was found in the way Firefox handled the HTML
  frameset tag. A web page with a frameset tag containing large values for
  the 'rows' and 'cols' attributes could trigger this flaw, possibly leading
  to arbitrary code execution with the privileges of the user running
  Firefox. (CVE-2011-0077)

  A flaw was found in the way Firefox handled the HTML iframe tag. A web page
  with an iframe tag containing a specially-crafted source address could
  trigger this flaw, possibly leading to arbitrary code execution with the
  privileges of the user running Firefox. (CVE-2011-0075)

  A flaw was found in the way Firefox displayed multiple marquee elements. A
  malformed HTML document could cause Firefox to execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2011-0074)

  A flaw was found in the way Firefox handled the nsTreeSelection element.
  Malformed content could cause Firefox to execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2011-0073)

  A use-after-free flaw was found in the way Firefox appended frame and
  iframe elements to a DOM tree when the NoScript add-on was enabled.
  Malicious HTML content could cause Firefox to execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2011-0072)

  A directory traversal flaw was found in the Firefox resource:// protocol
  handler. Malicious content could cause Firefox to access arbitrary files
  accessible to the user running Firefox. (CVE-2011-0071)

  A double free flaw was found in the way Firefox handled
  'application/http-index-format' documents. A malformed HTTP response could
  cause Firefox to execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2011-0070)

  A flaw was foun ...

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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.17~1.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.6.17~1.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.2.17~3.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-debuginfo", rpm:"xulrunner-debuginfo~1.9.2.17~3.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.2.17~3.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.17~2.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-debuginfo", rpm:"firefox-debuginfo~3.6.17~2.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
