# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802334");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Simple Machines Forum Session Hijacking Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69056");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49078");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17637/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SMF/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive
  information such as user's session credentials and may aid in further attacks.");

  script_tag(name:"affected", value:"Simple Machines Forum (SMF) 2.0");

  script_tag(name:"insight", value:"The flaw exists due to improper handling of user's sessions,
  allowing a remote attacker to hijack a valid user's session via a specially crafted link.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Simple Machines Forum is prone to session hijacking vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

smfPort = http_get_port(default:80);

ver = get_version_from_kb(port:smfPort, app:"SMF");
if(!ver)
  exit(0);

if(version_is_equal(version:ver, test_version:"2.0")){
  security_message(smfPort);
}
