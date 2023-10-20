# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811923");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-11786");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-10-11 09:14:12 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Lync 2013 Service Pack 1 Elevation of Privilege Vulnerability (KB4011179)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011179");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error when Skype for
  Business fails to properly handle specific authentication requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited this vulnerability to steal an authentication hash
  that can be reused elsewhere. The attacker could then take any action that the
  user had permissions for, causing possible outcomes that could vary between
  users.");

  script_tag(name:"affected", value:"- Microsoft Lync 2013 Service Pack 1 (32-bit)

  - Microsoft Lync 2013 Service Pack 1 (64-bit)");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011179");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101156");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_lync_detect_win.nasl");
  script_mandatory_keys("MS/Lync/Installed");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(get_kb_item("MS/Lync/Ver"))
{
  lyncPath = get_kb_item("MS/Lync/path");

  ## For MS Lync Basic
  if(!lyncPath){
    lyncPath = get_kb_item("MS/Lync/Basic/path");
  }

  if(lyncPath)
  {
    lyncPath1 = lyncPath + "OFFICE15";

    commVer = fetch_file_version(sysPath:lyncPath1, file_name:"Rtmpltfm.dll");
    if(commVer)
    {
      if(commVer =~ "^5" && version_in_range(version:commVer, test_version:"5.0", test_version2:"5.0.8687.156"))
      {
        report = 'File checked:     ' + lyncPath1 + "\Rtmpltfm.dll" + '\n' +
                 'File version:     ' + commVer  + '\n' +
                 'Vulnerable range: ' + "5.0 - 5.0.8687.156" + '\n' ;
        security_message(data:report);
      }
    }
  }
}
exit(0);
