###############################################################################
# OpenVAS Vulnerability Test
#
# SNMP Read Installed Software Packages
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106913");
  script_version("2021-03-24T10:08:26+0000");
  script_tag(name:"last_modification", value:"2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-06-29 15:32:58 +0700 (Thu, 29 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SNMP Read Installed Software Packages");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdescr_detect.nasl", "toolcheck.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available", "Tools/Present/libsnmp");

  script_tag(name:"summary", value:"This script reads the installed software packages on Linux devices over
  SNMP and saves them in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("snmp_func.inc");

port    = snmp_get_port(default: 161);
sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc || ("Linux" >!< sysdesc && sysdesc !~ "(Free|Net|Open)BSD"))
  exit(0);

# we limit it to max 800 entries
for (i = 1; i <= 800; i++) {
  oid = "1.3.6.1.2.1.25.6.3.1.2." + i;

  res = snmp_get(port: port, oid: oid);

  if (!res)
    break;

  sw += oid + '|' + res + '|';
}

if (sw) {
  set_kb_item(name: "SNMP/installed_software/available", value: TRUE);
  set_kb_item(name: "SNMP/" + port + "/installed_software", value: sw);
}

exit(0);
