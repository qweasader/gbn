###############################################################################
# OpenVAS Vulnerability Test
#
# Huawei VP9660 Multi-Point Control Unit Detection (SNMP)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806636");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2015-12-01 11:03:03 +0530 (Tue, 01 Dec 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Huawei VP9660 Multi-Point Control Unit Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Huawei VP9660 Multi-Point Control Unit (MCU).");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdescr_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/enterprise-communications/vp9660-pid-7951688");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default:161);

sysdesc = snmp_get_sysdescr(port:port);
if (!sysdesc || "HUAWEI VP9660" >!< sysdesc)
  exit(0);

concluded = sysdesc;
vers = "unknown";

vers = eregmatch(pattern:"HUAWEI VP9660 ([A-Z0-9a-z]+) ", string:sysdesc);
if (!isnull(vers[1])) {
  concluded = vers[0];
  version = vers[1];
}

set_kb_item(name:"huawei/mcu/detected", value:TRUE);
set_kb_item(name:"huawei/data_communication_product/detected", value:TRUE);

os_cpe = build_cpe(value:tolower(version), exp:"(v[0-9a-z]+)", base:"cpe:/o:huawei:vp_9660_firmware:");
if (!os_cpe)
  os_cpe = "cpe:/o:huawei:vp_9660_firmware";

os_register_and_report(os:"Huawei VP9660 MCU Firmware", cpe:os_cpe, desc:"Huawei VP9660 Multi-Point Control Unit Detection (SNMP)", runs_key:"unixoide");

hw_cpe = "cpe:/h:huawei:vp9660";

register_product(cpe:os_cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp");
register_product(cpe:hw_cpe, location:port + "/udp", port:port, proto:"udp", service:"snmp");

report = build_detection_report(app:"Huawei VP9660 MCU Firmware",
                                version:version,
                                install:port + "/udp",
                                cpe:os_cpe);
report += '\n\n';
report += build_detection_report(app:"Huawei VP9660 MCU",
                                 skip_version:TRUE,
                                 install:port + "/udp",
                                 cpe:hw_cpe);
report += '\n\nConcluded from SNMP sysDescr OID: ' + concluded;

log_message(data:report, port:port, proto:"udp");

exit(0);
