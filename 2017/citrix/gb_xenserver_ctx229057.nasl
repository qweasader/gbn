###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix XenServer Security Update (CTX229057)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140450");
  script_version("2021-09-14T13:01:54+0000");
  script_tag(name:"last_modification", value:"2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-10-25 09:32:33 +0700 (Wed, 25 Oct 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-15597");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenServer Security Update (CTX229057)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Citrix Xenserver Local Security Checks");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  script_tag(name:"summary", value:"A security vulnerability has been identified in Citrix XenServer that may
  allow a malicious administrator of a guest VM to compromise the host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2017-15597: pin count / page reference race in grant table code");

  script_tag(name:"affected", value:"XenServer versions 7.2, 7.1, 7.0, 6.5");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX229057");

  exit(0);
}

include("citrix_version_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("misc_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (!hotfixes = get_kb_item("xenserver/patches"))
  exit(0);

patches = make_array();

patches['7.2.0'] = make_list('XS72E009');
patches['7.1.0'] = make_list('XS71E017');
patches['7.0.0'] = make_list('XS70E047');
patches['6.5.0'] = make_list('XS65ESP1063');

citrix_xenserver_check_report_is_vulnerable(version: version, hotfixes: hotfixes, patches: patches);

exit(99);
