# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.811737");
  script_version("2022-10-20T10:12:23+0000");
  script_tag(name:"last_modification", value:"2022-10-20 10:12:23 +0000 (Thu, 20 Oct 2022)");
  script_tag(name:"creation_date", value:"2017-09-11 19:06:34 +0530 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ivanti Connect Secure Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Ivanti Connect Secure,
  formerly known as Pulse Connect Secure.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);
if(!sysdesc)
  exit(0);

if (sysdesc =~ "(Ivanti|Pulse) Connect Secure" && "Pulse Secure" >< sysdesc) {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "pulsesecure/detected", value: TRUE);
  set_kb_item(name: "pulsesecure/snmp/port", value: port);
  set_kb_item(name: "pulsesecure/snmp/" + port + "/concluded", value: sysdesc);

  # Pulse Secure,LLC,Pulse Connect Secure,MAG-SM160,8.1R7 (build 41041)
  # Pulse Secure, LLC,Ivanti Connect Secure,PSA-3000,9.1R14 (build 16847)
  details = eregmatch(pattern: "Connect Secure,([^,]+),([0-9R.]+)", string: sysdesc);
  if (!isnull(details[1])) {
    model = details[1];
    version = details[2];
  }

  set_kb_item(name: "pulsesecure/snmp/" + port + "/version", value: version);
  set_kb_item(name: "pulsesecure/snmp/" + port + "/model", value: model);
}

exit(0);
