# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902240");
  script_version("2021-09-01T09:31:49+0000");
  script_tag(name:"last_modification", value:"2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3129");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("uTorrent File Opening Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41051");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14726/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2164");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_utorrent_detect_portable_win.nasl");
  script_mandatory_keys("utorrent/win/version");

  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain libraries
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a Torrent file.");
  script_tag(name:"solution", value:"Upgrade to uTorrent version 2.0.4 or later.");
  script_tag(name:"summary", value:"uTorrent on this host is prone to insecure library
  loading vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute arbitrary code and
  conduct DLL hijacking attacks.");
  script_tag(name:"affected", value:"uTorrent version 2.0.3 and prior");

  script_xref(name:"URL", value:"http://www.utorrent.com/downloads");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

uTorrentVer = get_kb_item("utorrent/win/version");

if(!uTorrentVer) exit(0);

if(version_is_less_equal(version:uTorrentVer, test_version:"2.0.3")) {
      report = report_fixed_ver(installed_version:uTorrentVer, vulnerable_range:"Less than or equal to 2.0.3");
      security_message(port: 0, data: report);
}

exit(0);
