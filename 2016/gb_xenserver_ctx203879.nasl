###############################################################################
# OpenVAS Vulnerability Test
#
# Citrix XenServer Multiple Security Updates (CTX203879)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105528");
  script_cve_id("CVE-2015-8554", "CVE-2015-8104", "CVE-2015-8555");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_version("2021-10-14T10:01:27+0000");

  script_name("Citrix XenServer Multiple Security Updates (CTX203879)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX203879");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been
  identified in Citrix XenServer that could, in certain configurations, allow a
  malicious administrator of a guest VM to compromise the host or obtain potentially
  sensitive information from other guest VMs. In addition, a vulnerability has been
  identified that would allow certain applications running on a guest to cause that guest to crash.");

  script_tag(name:"affected", value:"Citrix XenServer up to and including Citrix XenServer 6.5 Service Pack 1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2021-10-14 10:01:27 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-01-26 12:17:18 +0100 (Tue, 26 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("citrix_version_func.inc");
include("host_details.inc");
include("list_array_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") )
  exit( 0 );

patches = make_array();

patches['6.5.0'] = make_list( 'XS65ESP1020', 'XS65ESP1021' );
patches['6.2.0'] = make_list( 'XS62ESP1037', 'XS62ESP1038' );
patches['6.1.0'] = make_list( 'XS61E063', 'XS61E064' );
patches['6.0.2'] = make_list( 'XS602E050', 'XS602ECC026', 'XS602ECC027' );
patches['6.0.0'] = make_list( 'XS60E055', 'XS60E056' );

citrix_xenserver_check_report_is_vulnerable( version:version, hotfixes:hotfixes, patches:patches );

exit( 99 );
