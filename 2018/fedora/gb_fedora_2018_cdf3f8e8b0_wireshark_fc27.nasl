###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for wireshark FEDORA-2018-cdf3f8e8b0
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.874288");
  script_version("2021-06-10T11:00:22+0000");
  script_tag(name:"last_modification", value:"2021-06-10 11:00:22 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-03-28 08:58:33 +0200 (Wed, 28 Mar 2018)");
  script_cve_id("CVE-2018-7419", "CVE-2018-7418", "CVE-2018-7417", "CVE-2018-7420",
                "CVE-2018-7320", "CVE-2018-7336", "CVE-2018-7337", "CVE-2018-7334",
                "CVE-2018-7335", "CVE-2018-6836", "CVE-2018-5335", "CVE-2018-5334",
                "CVE-2017-6014", "CVE-2017-9616", "CVE-2017-9617", "CVE-2017-9766",
                "CVE-2017-17997");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for wireshark FEDORA-2018-cdf3f8e8b0");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"wireshark on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"FEDORA", value:"2018-cdf3f8e8b0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2KD7XZZ37MHNPXTQLGQS6XHC754ZQMM6");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~2.4.5~3.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
