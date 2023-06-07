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
  script_oid("1.3.6.1.4.1.25623.1.0.900977");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3948");

  script_name("COWON Media Center JetAudio .wav File Denial Of Service Vulnerability");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cowon_jetaudio_detect.nasl");
  script_mandatory_keys("JetAudio/Ver");

  script_tag(name:"summary", value:"COWON Media Center JetAudio is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"An error occurs while parsing a .wav file containing an overly long string
  at the end.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to corrupt memory and cause the application
  to crash.");
  script_tag(name:"affected", value:"COWON Media Center JetAudio 7.5.3 on Windows.");

  script_tag(name:"solution", value:"Upgrade to COWON Media Center JetAudio version 8.0.6 or later");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9139");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51697");

  exit(0);
}

include("version_func.inc");

if( !version = get_kb_item("JetAudio/Ver" ) )
  exit( 0 );

if( version_is_equal( version:version, test_version:"7.5.3.15" ) ) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Equal to 7.5.3.15");
  security_message(port: 0, data: report);
  exit( 0 );
}

exit(99);
