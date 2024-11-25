# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807370");
  script_version("2024-02-20T05:05:48+0000");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-10-03 19:17:45 +0530 (Mon, 03 Oct 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player Buffer Overflow Vulnerability (Oct 2016)");

  script_tag(name:"summary", value:"VLC media player is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user supplied input while opening a file in player.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to cause denial of service condition.");

  script_tag(name:"affected", value:"VideoLAN VLC media player 2.2.3 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.2.4.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40439");
  script_xref(name:"URL", value:"https://www.videolan.org/security/sa1601.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vlcVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:vlcVer, test_version:"2.2.4"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"2.2.4");
  security_message(data:report);
  exit(0);
}
