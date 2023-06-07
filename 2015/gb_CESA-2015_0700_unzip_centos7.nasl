###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for unzip CESA-2015:0700 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882143");
  script_version("2021-10-15T12:02:59+0000");
  script_tag(name:"last_modification", value:"2021-10-15 12:02:59 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-04-01 07:23:28 +0200 (Wed, 01 Apr 2015)");
  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141", "CVE-2014-9636");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-05 20:50:00 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for unzip CESA-2015:0700 centos7");
  script_tag(name:"summary", value:"Check the version of unzip");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The unzip utility is used to list, test, or extract files from a
zip archive.

A buffer overflow was found in the way unzip uncompressed certain extra
fields of a file. A specially crafted Zip archive could cause unzip to
crash or, possibly, execute arbitrary code when the archive was tested with
unzip's '-t' option. (CVE-2014-9636)

A buffer overflow flaw was found in the way unzip computed the CRC32
checksum of certain extra fields of a file. A specially crafted Zip archive
could cause unzip to crash when the archive was tested with unzip's '-t'
option. (CVE-2014-8139)

An integer underflow flaw, leading to a buffer overflow, was found in the
way unzip uncompressed certain extra fields of a file. A specially crafted
Zip archive could cause unzip to crash when the archive was tested with
unzip's '-t' option. (CVE-2014-8140)

A buffer overflow flaw was found in the way unzip handled Zip64 files.
A specially crafted Zip archive could possibly cause unzip to crash when
the archive was uncompressed. (CVE-2014-8141)

Red Hat would like to thank oCERT for reporting the CVE-2014-8139,
CVE-2014-8140, and CVE-2014-8141 issues. oCERT acknowledges Michele
Spagnuolo of the Google Security Team as the original reporter of
these issues.

All unzip users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"unzip on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0700");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-April/021042.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.0~15.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}