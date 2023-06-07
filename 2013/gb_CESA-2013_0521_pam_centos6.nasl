###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pam CESA-2013:0521 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019462.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881657");
  script_version("2022-05-31T14:55:16+0100");
  script_tag(name:"last_modification", value:"2022-05-31 14:55:16 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2013-03-12 10:01:03 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2011-3148", "CVE-2011-3149");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2013:0521");
  script_name("CentOS Update for pam CESA-2013:0521 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"pam on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Pluggable Authentication Modules (PAM) provide a system whereby
  administrators can set up authentication policies without having to
  recompile programs to handle authentication.

  A stack-based buffer overflow flaw was found in the way the pam_env module
  parsed users' '~/.pam_environment' files. If an application's PAM
  configuration contained 'user_readenv=1' (this is not the default), a
  local attacker could use this flaw to crash the application or, possibly,
  escalate their privileges. (CVE-2011-3148)

  A denial of service flaw was found in the way the pam_env module expanded
  certain environment variables. If an application's PAM configuration
  contained 'user_readenv=1' (this is not the default), a local attacker
  could use this flaw to cause the application to enter an infinite loop.
  (CVE-2011-3149)

  Red Hat would like to thank Kees Cook of the Google ChromeOS Team for
  reporting the CVE-2011-3148 and CVE-2011-3149 issues.

  These updated pam packages include numerous bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Users
  are directed to the Red Hat Enterprise Linux 6.4 Technical Notes, linked
  to in the References, for information on the most significant of these
  changes.

  All pam users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues and add these
  enhancements.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"pam", rpm:"pam~1.1.1~13.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.1.1~13.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}