# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106149");
  script_version("2021-10-11T10:01:25+0000");
  script_tag(name:"last_modification", value:"2021-10-11 10:01:25 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-07-22 14:30:27 +0700 (Fri, 22 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 19:49:00 +0000 (Tue, 20 Apr 2021)");

  script_cve_id("CVE-2016-3973");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver AS Java Information Disclosure Vulnerability (2255990)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_sap_netweaver_as_java_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_sap_netweaver_portal_http_detect.nasl", "gsf/gb_sap_netweaver_as_http_detect.nasl");
  script_mandatory_keys("sap/netweaver/as/http/detected");

  script_tag(name:"summary", value:"SAP NetWeaver Application Server (AS) Java is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if WD_CHAT is accessible.");

  script_tag(name:"insight", value:"The chat feature in the Real-Time Collaboration (RTC) services
  allows remote attackers to obtain sensitive user information.");

  script_tag(name:"impact", value:"An unauthenticated attacker can get information about SAP
  NetWeaver AS Java users.");

  script_tag(name:"affected", value:"SAP NetWeaver AS Java version 7.10 (7.1) through 7.50 (7.5).");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://erpscan.io/advisories/erpscan-16-016-sap-netweaver-7-4-information-disclosure-wd_chat/");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2255990");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

# NetWeaver Portal is running on NetWeaver AS Java. We want to check / use both just to be sure if
# e.g. the AS Java banner is hidden. cpe:/a:sap:netweaver_as is used as a last fallback to throw all
# AS / Portal related active VTs against all possible deployments.
cpe_list = make_list("cpe:/a:sap:netweaver_application_server_java", "cpe:/a:sap:netweaver_portal", "cpe:/a:sap:netweaver_as");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, service: "www", first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!infos = get_app_version_and_location(cpe: cpe, port: port, exit_no_version:FALSE))
  exit(0);

version = infos["version"];
if (version && version !~ "^7\.[1-5]")
  exit(0);

dir = infos["location"];

if (dir == "/" || dir =~ "^[0-9]+/tcp$") # nb: gb_sap_netweaver_as_http_detect.nasl is setting e.g. 443/tcp
  dir = "";

url = dir + "/webdynpro/resources/sap.com/tc~rtc~coll.appl.rtc~wd_chat/Chat";

if (http_vuln_check(port: port, url: url, pattern: "set-cookie", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);