# Copyright (C) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140156");
  script_version("2022-03-16T07:44:03+0000");
  script_tag(name:"last_modification", value:"2022-03-16 07:44:03 +0000 (Wed, 16 Mar 2022)");
  script_tag(name:"creation_date", value:"2017-02-09 13:57:20 +0100 (Thu, 09 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");

  script_cve_id("CVE-2016-7542");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiOS Local Admin Password Hash Leak Vulnerability (FG-IR-16-050)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("forti/FortiOS/version");

  script_tag(name:"summary", value:"Fortinet FortiOS is prone to a local admin password hash leak
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A read-only administrator may have access to read-write
  administrators password hashes (not including super-admins) stored on the appliance via the webui
  REST API, and may therefore be able to crack them.");

  script_tag(name:"affected", value:"FortiOS version 5.2.0 through 5.2.9 and 5.4.1.");

  script_tag(name:"solution", value:"Update to version 5.2.10 GA, 5.4.2 GA or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-16-050");

  exit(0);
}

include("version_func.inc");

if( ! version = get_kb_item( "forti/FortiOS/version" ) )
  exit( 0 );

if( version =~ "^5\.2" )
  fix = "5.2.10";
else if( version =~ "^5\.4" )
  fix = "5.4.2";

if( ! fix ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
