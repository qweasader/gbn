###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openssl FEDORA-2015-4300
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
  script_oid("1.3.6.1.4.1.25623.1.0.869125");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-03-24 07:02:35 +0100 (Tue, 24 Mar 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-0209", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0287",
                "CVE-2015-0286", "CVE-2015-0288", "CVE-2015-0293", "CVE-2014-3570",
                "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204",
                "CVE-2015-0205", "CVE-2015-0206", "CVE-2014-3567", "CVE-2014-3513",
                "CVE-2014-3566", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507",
                "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511",
                "CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221",
                "CVE-2014-0224", "CVE-2014-3470", "CVE-2014-0160", "CVE-2013-4353",
                "CVE-2013-6450", "CVE-2013-6449");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for openssl FEDORA-2015-4300");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"openssl on Fedora 20");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-4300");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-March/152844.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC20");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~42.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
