##############################################################################
# OpenVAS Vulnerability Test
#
# HPE Comware Network Products Remote Information Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:comware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106460");
  script_version("2022-08-01T10:11:45+0000");
  script_tag(name:"last_modification", value:"2022-08-01 10:11:45 +0000 (Mon, 01 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-12-09 13:42:32 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 11:27:00 +0000 (Thu, 28 Jul 2022)");

  script_cve_id("CVE-2016-2183");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HPE Comware Network Products Remote Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_comware_platform_detect_snmp.nasl", "gb_hp_comware_platform_detect_ssh.nasl", "secpod_ssl_ciphers.nasl");
  script_mandatory_keys("hp/comware_device", "secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");

  script_tag(name:"summary", value:"HPE Comware 5 and Comware 7 network products are prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if DES and 3DES ciphers are enabled on the SSL ports.");

  script_tag(name:"insight", value:"A potential security vulnerability in the DES/3DES block ciphers could
  potentially impact HPE Comware 5 and Comware 7 network products using SSL/TLS.");

  script_tag(name:"impact", value:"This vulnerability could be exploited remotely resulting in disclosure of
  information.");

  script_tag(name:"affected", value:"Comware 5 and Comware 7 Products: All versions");

  script_tag(name:"solution", value:"For mitigation HPE recommends disabling DES and 3DES ciphers.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05349499");

  exit(0);
}

include("host_details.inc");
include("ssl_funcs.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^[57]") {
  port = tls_ssl_get_port();
  if (!port)
    exit(0);

  weakciphers = get_kb_list("secpod_ssl_ciphers/*/" + port + "/supported_ciphers");
  if (weakciphers =~ "_3?DES_") {
    security_message(port: port);
    exit(0);
  }
}

exit(0);
