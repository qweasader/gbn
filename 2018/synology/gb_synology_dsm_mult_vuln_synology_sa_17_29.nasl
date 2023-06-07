###############################################################################
# OpenVAS Vulnerability Test
#
# Synology DiskStation Manager (DSM) Multiple Vulnerabilities(Synology-SA-17:29)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813737");
  script_version("2022-12-05T10:11:03+0000");
  script_cve_id("CVE-2017-9553", "CVE-2017-9554");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-12 02:29:00 +0000 (Fri, 12 Jan 2018)");
  script_tag(name:"creation_date", value:"2018-07-31 12:20:00 +0530 (Tue, 31 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Synology DiskStation Manager (DSM) Multiple Vulnerabilities(Synology-SA-17:29)");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check if response is confirming valid username information.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A design flaw in Synology DiskStation Manager (DSM).

  - An information exposure vulnerability in Synology DiskStation Manager (DSM).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the encryption protection mechanism and steal account,
  password details. Also attacker can obtain user information via a brute-force
  attack.");

  script_tag(name:"affected", value:"Synology DiskStation Manager (DSM) versions
  5.2, 6.0 and 6.1");

  script_tag(name:"solution", value:"Upgrade to Synology DiskStation Manager (DSM)
  version 6.1.3-15152 or 6.0.3-8754-4 or 5.2-5967-04 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.synology.com/en-global/support/security/Synology_SA_17_29_DSM");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43455");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/http/detected");
  script_require_ports("Services/www", 5000);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

## Vulnerable set-up will return either 'msg : 1' if valid username,
## or 'msg : 2' if invalid username. Non-Vulnerable set-up will return 'msg : 3'
url = "/webman/forget_passwd.cgi?user=admin" ;
req = http_get_req(port:port, url:url);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200")
{
  ## Fixed versions
  if('"msg" : 3' >< res){
    exit(0);
  }

  ## Vulnerable versions
  if(('"msg" : 1' >< res || '"msg" : 2' >< res) && '"info" : "' >< res)
  {
    report = http_report_vuln_url(port:port, url: url);
    security_message(port:port, data: report);
    exit(0);
  }
}
