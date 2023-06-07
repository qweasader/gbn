# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900958");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3163");
  script_name("SILC Client Channel Name Format String Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_silc_prdts_detect.nasl");
  script_mandatory_keys("SILC/Client/Ver");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/09/03/5");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36193");

  script_tag(name:"impact", value:"Attackers can exploit this iisue to execute arbitrary code in the
  context of the affected application and compromise the system.");

  script_tag(name:"affected", value:"SILC Client 1.1.8 and prior

  SILC Toolkit prior to 1.1.10");

  script_tag(name:"insight", value:"Multiple format string errors occur in 'lib/silcclient/command.c' while
  processing format string specifiers in the channel name field.");

  script_tag(name:"summary", value:"SILC Client is prone to a format string vulnerability.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to SILC Toolkit 1.1.10.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:silcnet:silc_client";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "1.1.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.1.10" );
  security_message(port: 0, data: report);
  exit(0);
}

exit( 99 );
