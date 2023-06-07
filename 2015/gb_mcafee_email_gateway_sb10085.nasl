###############################################################################
# OpenVAS Vulnerability Test
#
# McAfee Email Gateway - Bash Shellshock Code Injection Exploit
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:mcafee:email_gateway";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105156");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2022-08-09T10:11:17+0000");

  script_name("McAfee Email Gateway - Bash Shellshock Code Injection Exploit");

  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10085");

  script_tag(name:"vuldetect", value:"Check the installed version and hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in the
`bash' component of several McAfee products.  These issues include those known as `Shellshock'");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2015-01-07 17:42:14 +0100 (Wed, 07 Jan 2015)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_email_gateway_version.nasl");
  script_mandatory_keys("mcafee_email_gateway/product_version", "mcafee_email_gateway/patches");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

product = get_kb_item("mcafee_email_gateway/product_name");
if( ! product ) product = 'McAfee Email Gateway';

if( ! patches = get_kb_item("mcafee_email_gateway/patches") ) exit( 0 );

if( version =~ "^7\.0\." )
{
  fixed = '7.0.2934.111';
  patch = '7.0.5h1010264';
}

else if (version =~ "^7\.5\.")
{
  fixed = "7.5.3088.112";
  patch = "7.5.4h1010253";
}

else if (version =~ "^7\.6\.")
{
  fixed = "7.6.3044.119";
  patch = "7.6.2h1010246";
}

else
 exit( 0 );

if( patch >< patches ) exit( 99 );

if( version_is_less( version:version, test_version:fixed ) )
{
  report = product + ' (' + version + ') is missing the patch ' + patch + '.\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 0 );
