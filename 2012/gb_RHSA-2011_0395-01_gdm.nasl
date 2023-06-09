###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gdm RHSA-2011:0395-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-March/msg00045.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870684");
  script_version("2022-05-31T15:35:19+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:35:19 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2012-06-06 10:46:12 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-0727");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2011:0395-01");
  script_name("RedHat Update for gdm RHSA-2011:0395-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"gdm on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The GNOME Display Manager (GDM) provides the graphical login screen, shown
  shortly after boot up, log out, and when user-switching.

  A race condition flaw was found in the way GDM handled the cache
  directories used to store users' dmrc and face icon files. A local attacker
  could use this flaw to trick GDM into changing the ownership of an
  arbitrary file via a symbolic link attack, allowing them to escalate their
  privileges. (CVE-2011-0727)

  Red Hat would like to thank Sebastian Krahmer of the SuSE Security Team for
  reporting this issue.

  All users should upgrade to these updated packages, which contain a
  backported patch to correct this issue. GDM must be restarted for this
  update to take effect. Rebooting achieves this, but changing the runlevel
  from 5 to 3 and back to 5 also restarts GDM.");
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

  if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.30.4~21.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-debuginfo", rpm:"gdm-debuginfo~2.30.4~21.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-libs", rpm:"gdm-libs~2.30.4~21.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-plugin-fingerprint", rpm:"gdm-plugin-fingerprint~2.30.4~21.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-plugin-smartcard", rpm:"gdm-plugin-smartcard~2.30.4~21.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdm-user-switch-applet", rpm:"gdm-user-switch-applet~2.30.4~21.el6_0.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
