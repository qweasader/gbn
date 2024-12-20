# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882102");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-23 14:58:26 +0100 (Fri, 23 Jan 2015)");
  script_cve_id("CVE-2014-8157", "CVE-2014-8158");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for jasper CESA-2015:0074 centos6");
  script_tag(name:"summary", value:"Check the version of jasper");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"JasPer is an implementation of Part 1 of the JPEG 2000 image compression
standard.

An off-by-one flaw, leading to a heap-based buffer overflow, was found in
the way JasPer decoded JPEG 2000 image files. A specially crafted file
could cause an application using JasPer to crash or, possibly, execute
arbitrary code. (CVE-2014-8157)

An unrestricted stack memory use flaw was found in the way JasPer decoded
JPEG 2000 image files. A specially crafted file could cause an application
using JasPer to crash or, possibly, execute arbitrary code. (CVE-2014-8158)

Red Hat would like to thank oCERT for reporting these issues. oCERT
acknowledges pyddeh as the original reporter.

All JasPer users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All applications using
the JasPer libraries must be restarted for the update to take effect.");
  script_tag(name:"affected", value:"jasper on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0074");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-January/020893.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~16.el6_6.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-devel", rpm:"jasper-devel~1.900.1~16.el6_6.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-libs", rpm:"jasper-libs~1.900.1~16.el6_6.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jasper-utils", rpm:"jasper-utils~1.900.1~16.el6_6.3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}