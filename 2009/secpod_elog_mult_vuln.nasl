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

CPE = "cpe:/a:stefan_ritt:elog_web_logbook";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901009");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7004", "CVE-2008-0444", "CVE-2008-0445");
  script_name("ELOG Remote Buffer Overflow and Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_elog_detect.nasl");
  script_mandatory_keys("ELOG/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/39903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27399");
  script_xref(name:"URL", value:"https://midas.psi.ch/elog/download/ChangeLog");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/0265");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary scripting
  code, cause a denial of service or compromise a vulnerable system.");

  script_tag(name:"affected", value:"ELOG versions prior to 2.7.1.");

  script_tag(name:"insight", value:"The flaws are due to:

  - A buffer overflow error in 'elog.c' when processing malformed data.

  - An infinite loop in the 'replace_inline_img()' [elogd.c] function.

  - An input validation error when handling the 'subtext' parameter.");

  script_tag(name:"solution", value:"Upgrade ELOG Version to 2.7.1. Please see the
  references for more info.");

  script_tag(name:"summary", value:"ELOG is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

# nb: 2.7.1 => 2.7.1.2002
if( version_is_less( version:vers, test_version:"2.7.1.2002" ) ){
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );