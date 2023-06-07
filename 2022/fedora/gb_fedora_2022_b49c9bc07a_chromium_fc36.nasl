# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.822612");
  script_version("2022-10-26T10:12:44+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-2007", "CVE-2022-2008", "CVE-2022-2010", "CVE-2022-2011", "CVE-2022-2603", "CVE-2022-2604", "CVE-2022-2605", "CVE-2022-2606", "CVE-2022-2607", "CVE-2022-2608", "CVE-2022-2609", "CVE-2022-2610", "CVE-2022-2611", "CVE-2022-2612", "CVE-2022-2613", "CVE-2022-2614", "CVE-2022-2615", "CVE-2022-2616", "CVE-2022-2617", "CVE-2022-2618", "CVE-2022-2619", "CVE-2022-2620", "CVE-2022-2621", "CVE-2022-2622", "CVE-2022-2623", "CVE-2022-2624", "CVE-2022-2852", "CVE-2022-2854", "CVE-2022-2855", "CVE-2022-2857", "CVE-2022-2858", "CVE-2022-2853", "CVE-2022-2856", "CVE-2022-2859", "CVE-2022-2860", "CVE-2022-2861", "CVE-2022-3038", "CVE-2022-3039", "CVE-2022-3040", "CVE-2022-3041", "CVE-2022-3042", "CVE-2022-3043", "CVE-2022-3044", "CVE-2022-3045", "CVE-2022-3046", "CVE-2022-3071", "CVE-2022-3047", "CVE-2022-3048", "CVE-2022-3049", "CVE-2022-3050", "CVE-2022-3051", "CVE-2022-3052", "CVE-2022-3053", "CVE-2022-3054", "CVE-2022-3055", "CVE-2022-3056", "CVE-2022-3057", "CVE-2022-3058", "CVE-2022-3075", "CVE-2022-3195", "CVE-2022-3196", "CVE-2022-3197", "CVE-2022-3198", "CVE-2022-3199", "CVE-2022-3200", "CVE-2022-3201");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-10-26 10:12:44 +0000 (Wed, 26 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-05 07:36:47 +0000 (Wed, 05 Oct 2022)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2022-b49c9bc07a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-b49c9bc07a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ACB3ENEHQ55GVZKKYER7KSRXT3HUFV7D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2022-b49c9bc07a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 36.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~105.0.5195.125~2.fc36", rls:"FC36"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);