###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ipa-admintools CESA-2016:1797 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882553");
  script_version("2021-10-12T12:01:25+0000");
  script_tag(name:"last_modification", value:"2021-10-12 12:01:25 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-09-06 05:38:01 +0200 (Tue, 06 Sep 2016)");
  script_cve_id("CVE-2016-5404");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ipa-admintools CESA-2016:1797 centos6");
  script_tag(name:"summary", value:"Check the version of ipa-admintools");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Red Hat Identity Management (IdM) is a
centralized authentication, identity management, and authorization solution for
both traditional and cloud-based enterprise environments.

Security Fix(es):

  * An insufficient permission check issue was found in the way IPA server
treats certificate revocation requests. An attacker logged in with the
'retrieve certificate' permission enabled could use this flaw to revoke
certificates, possibly triggering a denial of service attack.
(CVE-2016-5404)

This issue was discovered by Fraser Tweedale (Red Hat).");
  script_tag(name:"affected", value:"ipa-admintools on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1797");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-September/022057.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~3.0.0~50.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~3.0.0~50.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~3.0.0~50.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~3.0.0~50.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~3.0.0~50.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~3.0.0~50.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa", rpm:"ipa~3.0.0~50.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
