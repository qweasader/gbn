###############################################################################
# OpenVAS Vulnerability Test
#
# WS FTP server FTP bounce attack and PASV connection hijacking flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:ipswitch:ws_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14599");
  script_version("2022-08-15T10:52:44+0000");
  script_tag(name:"last_modification", value:"2022-08-15 10:52:44 +0000 (Mon, 15 Aug 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-1999-0017");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WS FTP Server Session Hijacking Vulnerability (Nov 2005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("FTP");
  script_dependencies("gb_progress_ws_ftp_server_consolidation.nasl");
  script_mandatory_keys("progress/ws_ftp/server/detected");

  script_tag(name:"summary", value:"WS_FTP server is prone to session hijacking during passive
  connections and to a FTP bounce attack when a user submits a specially crafted FTP command.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6051");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^[0-2]\.|3\.(0\.|1\.[0-3][^0-9])") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
