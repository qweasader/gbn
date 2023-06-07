################################################################################
# OpenVAS Vulnerability Test
#
# MediaWiki Frames Processing Clickjacking Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801900");
  script_version("2022-03-03T15:38:20+0000");
  script_tag(name:"last_modification", value:"2022-03-03 15:38:20 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-0003");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("MediaWiki < 1.16.1 Frames Processing Clickjacking Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl");
  script_mandatory_keys("mediawiki/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42810");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64476");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0017");
  script_xref(name:"URL", value:"http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-January/000093.html");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to hijack the
  victim's click actions and possibly launch further attacks against the victim.");

  script_tag(name:"affected", value:"MediaWiki version prior to 1.16.1.");

  script_tag(name:"insight", value:"The flaw is caused by input validation errors when processing
  certain data via frames, which could allow clickjacking attacks.");

  script_tag(name:"solution", value:"Update to version 1.16.1 or later.");

  script_tag(name:"summary", value:"MediaWiki is prone to a clickjacking information disclosure
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.16.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.16.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );