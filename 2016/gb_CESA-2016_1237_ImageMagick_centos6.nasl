# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882506");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-06-18 05:19:54 +0200 (Sat, 18 Jun 2016)");
  script_cve_id("CVE-2015-8895", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898",
                "CVE-2016-5118", "CVE-2016-5239", "CVE-2016-5240");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 18:21:00 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ImageMagick CESA-2016:1237 centos6");
  script_tag(name:"summary", value:"Check the version of ImageMagick");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ImageMagick is an image display and
manipulation tool for the X Window System that can read and write multiple image formats.

Security Fix(es):

  * It was discovered that ImageMagick did not properly sanitize certain
input before using it to invoke processes. A remote attacker could create a
specially crafted image that, when processed by an application using
ImageMagick or an unsuspecting user using the ImageMagick utilities, would
lead to arbitrary execution of shell commands with the privileges of the
user running the application. (CVE-2016-5118)

  * It was discovered that ImageMagick did not properly sanitize certain
input before passing it to the gnuplot delegate functionality. A remote
attacker could create a specially crafted image that, when processed by an
application using ImageMagick or an unsuspecting user using the ImageMagick
utilities, would lead to arbitrary execution of shell commands with the
privileges of the user running the application. (CVE-2016-5239)

  * Multiple flaws have been discovered in ImageMagick. A remote attacker
could, for example, create specially crafted images that, when processed by
an application using ImageMagick or an unsuspecting user using the
ImageMagick utilities, would result in a memory corruption and,
potentially, execution of arbitrary code, a denial of service, or an
application crash. (CVE-2015-8896, CVE-2015-8895, CVE-2016-5240,
CVE-2015-8897, CVE-2015-8898)");
  script_tag(name:"affected", value:"ImageMagick on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1237");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-June/021909.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.7.2.7~5.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.7.2.7~5.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++-devel", rpm:"ImageMagick-c++-devel~6.7.2.7~5.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.7.2.7~5.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.7.2.7~5.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.7.2.7~5.el6_8", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
