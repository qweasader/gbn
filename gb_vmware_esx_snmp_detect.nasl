###############################################################################
# OpenVAS Vulnerability Test
#
# VMware ESX detection (SNMP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103417");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2012-02-14 10:38:50 +0100 (Tue, 14 Feb 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("VMware ESX / ESXi Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_xref(name:"URL", value:"http://www.vmware.com/");

  script_tag(name:"summary", value:"SNMP based detection of VMware ESX / ESXi.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

SCRIPT_DESC = "VMware ESX / ESXi Detection (SNMP)";

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc || "vmware" >!< tolower(sysdesc))
  exit(0);

version = eregmatch(pattern:"(VMware ESX ?(Server)?) ([0-9.]+)", string:sysdesc);

if(!isnull(version[1]) && !isnull(version[3])) {

  typ = version[1];
  vers = version[3];

  if(vers > 0) {
    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/o:vmware:esx:"); # even if it is an "ESXi", there is just "ESX" in sysDescr.
    set_kb_item(name:"VMware/GSX-Server/snmp/version", value:vers);
  } else {
    cpe = "cpe:/o:vmware:esx";
    set_kb_item(name:"VMware/GSX-Server/snmp/version", value:"unknown");
    vers = "unknown";
  }

  os_register_and_report(os:"VMware ESX / ESXi", cpe:cpe, banner_type:"SNMP sysDescr OID", banner:sysdesc, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide");

  set_kb_item(name:"VMware/ESX/installed", value:TRUE);

  if("build" >< sysdesc) {
    build = eregmatch(pattern:" build-([0-9]+)", string:sysdesc);
    if(!isnull(build[1])) {
      replace_kb_item(name:"VMware/ESX/build", value:build[1]);
    }
  }

  result_txt = 'Detected ' + typ + ' Version: ';
  result_txt += vers;
  result_txt += '\nCPE: ' + cpe;
  result_txt += '\n\nConcluded from remote snmp sysDescr:\n';
  result_txt += sysdesc;
  result_txt += '\n';

  log_message(port:port, data:result_txt, proto:"udp");
}

exit(0);
