# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-September/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870826");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-17 16:40:43 +0530 (Mon, 17 Sep 2012)");
  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825",
                "CVE-2012-2870", "CVE-2012-2871");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2012:1265-01");
  script_name("RedHat Update for libxslt RHSA-2012:1265-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(6|5)");
  script_tag(name:"affected", value:"libxslt on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"libxslt is a library for transforming XML files into other textual formats
  (including HTML, plain text, and other XML representations of the
  underlying data) using the standard XSLT stylesheet transformation
  mechanism.

  A heap-based buffer overflow flaw was found in the way libxslt applied
  templates to nodes selected by certain namespaces. An attacker could use
  this flaw to create a malicious XSL file that, when used by an application
  linked against libxslt to perform an XSL transformation, could cause the
  application to crash or, possibly, execute arbitrary code with the
  privileges of the user running the application. (CVE-2012-2871)

  Several denial of service flaws were found in libxslt. An attacker could
  use these flaws to create a malicious XSL file that, when used by an
  application linked against libxslt to perform an XSL transformation, could
  cause the application to crash. (CVE-2012-2825, CVE-2012-2870,
  CVE-2011-3970)

  An information leak could occur if an application using libxslt processed
  an untrusted XPath expression, or used a malicious XSL file to perform an
  XSL transformation. If combined with other flaws, this leak could possibly
  help an attacker bypass intended memory corruption protections.
  (CVE-2011-1202)

  All libxslt users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. All running
  applications linked against libxslt must be restarted for this update to
  take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.26~2.el6_3.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-debuginfo", rpm:"libxslt-debuginfo~1.1.26~2.el6_3.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.26~2.el6_3.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.17~4.el5_8.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-debuginfo", rpm:"libxslt-debuginfo~1.1.17~4.el5_8.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.17~4.el5_8.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-python", rpm:"libxslt-python~1.1.17~4.el5_8.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
