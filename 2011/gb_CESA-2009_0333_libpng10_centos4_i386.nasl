# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015812.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880888");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0333");
  script_cve_id("CVE-2008-1382", "CVE-2009-0040");
  script_name("CentOS Update for libpng10 CESA-2009:0333 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng10'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"libpng10 on CentOS 4");
  script_tag(name:"insight", value:"The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A flaw was discovered in libpng that could result in libpng trying to
  free() random memory if certain, unlikely error conditions occurred. If a
  carefully-crafted PNG file was loaded by an application linked against
  libpng, it could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2009-0040)

  A flaw was discovered in the way libpng handled PNG images containing
  'unknown' chunks. If an application linked against libpng attempted to
  process a malformed, unknown chunk in a malicious PNG image, it could cause
  the application to crash. (CVE-2008-1382)

  Users of libpng and libpng10 should upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  applications using libpng or libpng10 must be restarted for the update to
  take effect.");
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

  if ((res = isrpmvuln(pkg:"libpng10", rpm:"libpng10~1.0.16~3.el4_7.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng10-devel", rpm:"libpng10-devel~1.0.16~3.el4_7.3", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.7~3.el4_7.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.7~3.el4_7.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
