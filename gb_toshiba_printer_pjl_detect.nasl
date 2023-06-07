# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.142900");
  script_version("2022-05-31T20:54:22+0100");
  script_tag(name:"last_modification", value:"2022-05-31 20:54:22 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2019-09-17 08:01:11 +0000 (Tue, 17 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (PJL)");

  script_tag(name:"summary", value:"This script performs Printer Job Language (PJL) based detection
  of Toshiba printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_pcl_pjl_detect.nasl");
  script_require_ports("Services/hp-pjl", 9100);
  script_mandatory_keys("hp-pjl/banner/available");

  exit(0);
}

port = get_kb_item("hp-pjl/port");

banner = get_kb_item("hp-pjl/" + port + "/banner");
if (!banner || banner !~ "^TOSHIBA ")
  exit(0);

set_kb_item(name: 'toshiba_printer/detected', value: TRUE);
set_kb_item(name: 'toshiba_printer/hp-pjl/detected', value: TRUE);
set_kb_item(name: 'toshiba_printer/hp-pjl/port', value: port);
set_kb_item(name: 'toshiba_printer/hp-pjl/' + port + '/concluded', value: banner);

# TOSHIBA e-STUDIO2505AC
# TOSHIBA e-STUDIO470P
# TOSHIBA e-STUDIO306CS
mod = eregmatch(pattern: "^TOSHIBA ([^ ]+)", string: banner);
if (!isnull(mod[1]))
  set_kb_item(name: 'toshiba_printer/hp-pjl/' + port + '/model', value: mod[1]);

exit(0);
