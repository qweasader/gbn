# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871295");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-11-19 06:34:48 +0100 (Wed, 19 Nov 2014)");
  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for libXfont RHSA-2014:1870-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libXfont'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libXfont packages provide the X.Org libXfont runtime library. X.Org is
an open source implementation of the X Window System.

A use-after-free flaw was found in the way libXfont processed certain font
files when attempting to add a new directory to the font path. A malicious,
local user could exploit this issue to potentially execute arbitrary code
with the privileges of the X.Org server. (CVE-2014-0209)

Multiple out-of-bounds write flaws were found in the way libXfont parsed
replies received from an X.org font server. A malicious X.org server could
cause an X client to crash or, possibly, execute arbitrary code with the
privileges of the X.Org server. (CVE-2014-0210, CVE-2014-0211)

Red Hat would like to thank the X.org project for reporting these issues.
Upstream acknowledges Ilja van Sprundel as the original reporter.

Users of libXfont should upgrade to these updated packages, which contain a
backported patch to resolve this issue. All running X.Org server instances
must be restarted for the update to take effect.");
  script_tag(name:"affected", value:"libXfont on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:1870-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-November/msg00035.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.7~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.4.7~2.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.4.5~4.el6_6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXfont-debuginfo", rpm:"libXfont-debuginfo~1.4.5~4.el6_6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}