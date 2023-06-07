###############################################################################
# OpenVAS Vulnerability Test
#
# Geneko Router Detection (SNMP)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107261");
  script_version("2021-03-24T10:08:26+0000");
  script_tag(name:"last_modification", value:"2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)");
  script_tag(name:"creation_date", value:"2017-11-17 14:42:26 +0700 (Fri, 17 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Geneko Router Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Geneko routers.");

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

if (!sysdesc)
  exit(0);

# Linux geneko 4.1.0-linux4sam_5.2-00047-g0bf8b22 #5 Fri May 10 08:52:13 CEST 2019 armv7l
# Linux geneko 3.18.21-geneko-linux4sam_4.7-rt19 #1 PREEMPT RT Wed Feb 10 10:05:39 CET 2016 armv7l
#
# Note: e.g. 4.1.0 is the Linux Kernel version, not the version of the router.
if ("Linux geneko" >< sysdesc) {
  version = "unknown";
  model = "unknown";

  set_kb_item(name: "geneko/router/detected", value: TRUE);
  set_kb_item(name: "geneko/router/snmp/port", value: port);
  set_kb_item(name: "geneko/router/snmp/" + port + "/concluded", value: sysdesc);
  set_kb_item(name: "geneko/router/snmp/" + port + "/version", value: version);
  set_kb_item(name: "geneko/router/snmp/" + port + "/model", value: model);
}

exit(0);
