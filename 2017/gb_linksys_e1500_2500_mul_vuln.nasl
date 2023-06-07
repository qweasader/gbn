###############################################################################
# OpenVAS Vulnerability Test
#
# Linksys E1500/E2500 Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107202");
  script_version("2021-10-12T09:28:32+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-12 09:28:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2017-11-02 11:57:11 +0530 (Thu, 02 Nov 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Linksys E1500/E2500 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Linksys E1500/E2500 devices are prone to multiple
  vulnerabilities.

  This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is caused by missing input validation in the
  ping_size parameter and can be exploited to inject and execute arbitrary shell commands.");

  script_tag(name:"impact", value:"The attacker can start a telnetd or upload and execute a backdoor
  to compromise the device.");

  script_tag(name:"affected", value:"Linksys E1500 v1.0.00 build 9, v1.0.04 build 2, v1.0.05 build 1
  and Linksys E2500 v1.0.03, probably all versions up to 2.0.00.");

  script_tag(name:"solution", value:"Update the firmware to version 1.0.06 build 1 for the E1500
  model. Update the firmware to version 2.0.00 build 1 for the E2500 model.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.s3cur1ty.de/m1adv2013-004");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");
  script_xref(name:"URL", value:"https://community.linksys.com/t5/Wireless-Routers/Re-Reaper-Botnet-Vulnerability/td-p/1224368");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_linksys_devices_consolidation.nasl");
  script_mandatory_keys("linksys/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:linksys:e1500_firmware",
                     "cpe:/o:linksys:e2500_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe == "cpe:/o:linksys:e1500_firmware") {
  if (version_is_less(version: version, test_version: "1.0.06")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.0.06 build 1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

else if (cpe == "cpe:/o:linksys:e2500_firmware") {
  if (version_is_less(version: version, test_version: "2.0.00")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.0.00 build 1");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);