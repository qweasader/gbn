# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800069");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2008-5109");
  script_name("Adobe Flash Media Server Video Stream Capture Security Issue");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/advisories/apsa08-11.html");

  script_tag(name:"impact", value:"Successful attack could lead to capture and archive delivered video.");

  script_tag(name:"affected", value:"Adobe Flash Media Server 3.0.x prior to 3.0.3 and 3.5.x prior to 3.5.1 on Windows.");

  script_tag(name:"insight", value:"The security issue is that it is possible to establish RTMPE/RTMPTE sessions
  to Flash Media Server when SWF verification is not enabled.");

  script_tag(name:"solution", value:"Upgrade Adobe Flash Media Server version 3.0.3, 3.5.1 or later.");

  script_tag(name:"summary", value:"Adobe Flash Media Server (FMS) is prone to a video streaming vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach entry (registry_enum_keys(key:key))
{
  fmsVer = registry_get_sz(key:key + entry, item:"DisplayName");
  if("Adobe Flash Media Server" >< fmsVer)
  {
    fmsVer = eregmatch(pattern:"([0-9.]+)", string:fmsVer);
    if(!isnull(fmsVer[1]))
    {
      if(version_is_less(version:fmsVer[1], test_version:"3.0.3") ||
        (fmsVer[1] =~ "^3\.5" && version_is_less(version:fmsVer[1], test_version:"3.5.1"))){
        report = report_fixed_ver(installed_version:fmsVer[1], fixed_version:"3.0.3/3.5.1");
        security_message(port:0, data:report);
      }
    }
    exit(0);
  }
}

exit(99);
