# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146700");
  script_version("2021-09-14T08:18:57+0000");
  script_tag(name:"last_modification", value:"2021-09-14 08:18:57 +0000 (Tue, 14 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-13 11:28:51 +0000 (Mon, 13 Sep 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("EFI Fiery Detection (FTP)");

  script_tag(name:"summary", value:"FTP based detection of EFI Fiery.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/efi/printer/detected");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);

# 220 EFI FTP Print server ready.
if (banner && "EFI FTP Print server" >< banner) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "efi/fiery/detected", value: TRUE);
  set_kb_item(name: "efi/fiery/ftp/detected", value: TRUE);
  set_kb_item(name: "efi/fiery/ftp/port", value: port);
  set_kb_item(name: "efi/fiery/ftp/" + port + "/concluded", value: banner);

  set_kb_item(name: "efi/fiery/ftp/" + port + "/model", value: model);
  set_kb_item(name: "efi/fiery/ftp/" + port + "/version", value: version);
}

exit(0);
