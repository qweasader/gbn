# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805738");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2531", "CVE-2015-2532", "CVE-2015-2536");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-09 11:34:04 +0530 (Wed, 09 Sep 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Lync Server Multiple Vulnerabilities (3089952)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-104.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to Server fails to
  properly sanitize specially crafted content.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct cross-site scripting attacks and information disclosure
  attack.");

  script_tag(name:"affected", value:"Microsoft Lync Server 2013 (Web Components Server).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3089952");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-104");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_lync_server_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Server/Name", "MS/Lync/Server/path");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

ms_lync_name = get_kb_item("MS/Lync/Server/Name");
if(!ms_lync_name){
  exit(0);
}

if("Microsoft Lync Server 2013" >< ms_lync_name)
{
  ms_lync_path = get_kb_item("MS/Lync/Server/path");
  if(ms_lync_path)
  {
    autodiscover = "\Web Components\Autodiscover\Ext\Bin\microsoft.rtc.internal.autodiscover.dll";

    autodiscover_ver = fetch_file_version(sysPath:ms_lync_path, file_name:autodiscover);
    if(autodiscover_ver)
    {
      if(version_in_range(version:autodiscover_ver, test_version:"5.0", test_version2:"5.0.8308.725"))
      {
         report = 'File checked:     ' + ms_lync_path + autodiscover + '\n' +
                  'File version:     ' + autodiscover_ver  + '\n' +
                  'Vulnerable range: 5.0 - 5.0.8308.725'  + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
