###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libsmbclient CESA-2016:0448 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882421");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-03-16 06:09:32 +0100 (Wed, 16 Mar 2016)");
  script_cve_id("CVE-2015-7560");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:03:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for libsmbclient CESA-2016:0448 centos6");
  script_tag(name:"summary", value:"Check the version of libsmbclient");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Samba is an open-source implementation of the Server Message Block (SMB) or
Common Internet File System (CIFS) protocol, which allows PC-compatible
machines to share files, printers, and other information.

A flaw was found in the way Samba handled ACLs on symbolic links.
An authenticated user could use this flaw to gain access to an arbitrary
file or directory by overwriting its ACL. (CVE-2015-7560)

Red Hat would like to thank the Samba project for reporting this issue.
Upstream acknowledges Jeremy Allison (Google) and the Samba team as the
original reporters.

All samba users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing this
update, the smb service will be restarted automatically.");
  script_tag(name:"affected", value:"libsmbclient on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0448");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021730.html");
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

  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind-devel", rpm:"samba-winbind-devel~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-glusterfs", rpm:"samba-glusterfs~3.6.23~25.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
