###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ImageMagick CESA-2016:0726 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882484");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-05-10 05:19:37 +0200 (Tue, 10 May 2016)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717",
                "CVE-2016-3718");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 13:29:00 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ImageMagick CESA-2016:0726 centos7");
  script_tag(name:"summary", value:"Check the version of ImageMagick");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"ImageMagick is an image display and
manipulation tool for the X Window System that can read and write multiple
image formats.

Security Fix(es):

  * It was discovered that ImageMagick did not properly sanitize certain
input before passing it to the delegate functionality. A remote attacker
could create a specially crafted image that, when processed by an
application using ImageMagick or an unsuspecting user using the ImageMagick
utilities, would lead to arbitrary execution of shell commands with the
privileges of the user running the application. (CVE-2016-3714)

  * It was discovered that certain ImageMagick coders and pseudo-protocols
did not properly prevent security sensitive operations when processing
specially crafted images. A remote attacker could create a specially
crafted image that, when processed by an application using ImageMagick or
an unsuspecting user using the ImageMagick utilities, would allow the
attacker to delete, move, or disclose the contents of arbitrary files.
(CVE-2016-3715, CVE-2016-3716, CVE-2016-3717)

  * A server-side request forgery flaw was discovered in the way ImageMagick
processed certain images. A remote attacker could exploit this flaw to
mislead an application using ImageMagick or an unsuspecting user using the
ImageMagick utilities into, for example, performing HTTP(S) requests or
opening FTP sessions via specially crafted images. (CVE-2016-3718)

Note: This update contains an updated /etc/ImageMagick/policy.xml file that
disables the EPHEMERAL, HTTPS, HTTP, URL, FTP, MVG, MSL, TEXT, and LABEL
coders. If you experience any problems after the update, it may be
necessary to manually adjust the policy.xml file to match your
requirements. Please take additional precautions to ensure that your
applications using the ImageMagick library do not process malicious or
untrusted files before doing so.");
  script_tag(name:"affected", value:"ImageMagick on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2016:0726");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021866.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.7.8.9~13.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.7.8.9~13.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++-devel", rpm:"ImageMagick-c++-devel~6.7.8.9~13.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.7.8.9~13.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.7.8.9~13.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.7.8.9~13.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
