###############################################################################
# OpenVAS Vulnerability Test
#
# Junos Kernel Panic Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/o:juniper:junos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105909");
  script_version("2023-01-20T10:11:50+0000");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"creation_date", value:"2014-05-05 10:49:18 +0700 (Mon, 05 May 2014)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2014-0614");

  script_name("Juniper Networks Junos OS Kernel Panic Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("JunOS Local Security Checks");
  script_dependencies("gb_juniper_junos_consolidation.nasl");
  script_mandatory_keys("juniper/junos/detected", "juniper/junos/build");

  script_tag(name:"summary", value:"Denial of Service Vulnerability through crafted IGMP packets.");

  script_tag(name:"insight", value:"Reception of a very high rate of crafted IGMP packets may cause
the Junos kernel to crash. The contents of the valid IGMP packets must be specifically crafted to trigger
the crash, while maintaining a transmit rate exceeding approximately 1000 packets per second. PIM must
also be enabled to trigger this crash.");

  script_tag(name:"impact", value:"Remote attackers can cause the kernel to crash resulting in a
Denial of Service condition.");

  script_tag(name:"affected", value:"Junos OS 13.2 and 13.3.");

  script_tag(name:"solution", value:"New builds of Junos OS software are available from Juniper. As
a workaround disable PIM if not required or if fxp0 is unused, disable the external management interface.");

  script_xref(name:"URL", value:"http://kb.juniper.net/JSA10618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66762");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("juniper/junos/build");
if (!build)
  exit(0);

desc += "Version/Build-Date:
" + version + " / " + build;

build2check = str_replace(string:build, find:"-", replace:"");

if (revcomp(a:build2check, b:"20140116") >= 0) {
  exit(99);
}

if (version =~ "^13") {
  if (revcomp(a:version, b:"13.2R3") < 0) {
    security_message(port:0, data:desc);
    exit(0);
  } else if ((revcomp(a:version, b:"13.3R1") < 0) &&
             (revcomp(a:version, b:"13.3") >= 0)) {
    security_message(port:0, data:desc);
    exit(0);
  }
}

exit(99);
