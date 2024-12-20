# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813526");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-0871", "CVE-2018-0978", "CVE-2018-0982", "CVE-2018-1036",
                "CVE-2018-1040", "CVE-2018-8111", "CVE-2018-8113", "CVE-2018-8121",
                "CVE-2018-8140", "CVE-2018-8169", "CVE-2018-8175", "CVE-2018-8201",
                "CVE-2018-8205", "CVE-2018-8207", "CVE-2018-8208", "CVE-2018-8209",
                "CVE-2018-8210", "CVE-2018-8211", "CVE-2018-8212", "CVE-2018-8213",
                "CVE-2018-8214", "CVE-2018-8215", "CVE-2018-8218", "CVE-2018-8219",
                "CVE-2018-8221", "CVE-2018-8225", "CVE-2018-8226", "CVE-2018-8227",
                "CVE-2018-8229", "CVE-2018-8231", "CVE-2018-8234", "CVE-2018-8235",
                "CVE-2018-8236", "CVE-2018-8239", "CVE-2018-8251", "CVE-2018-8267");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-06-13 09:05:09 +0530 (Wed, 13 Jun 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4284819)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4284819");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - When the Windows kernel improperly handles objects in memory.

  - When Windows improperly handles objects in memory.

  - When the (Human Interface Device) HID Parser Library driver improperly handles
    objects in memory.

  - In Device Guard that could allow an attacker to inject malicious code into a
    Windows PowerShell session.

  - In Windows when Desktop Bridge does not properly manage the virtual registry.

  - When Windows allows a normal user to access the Wireless LAN profile of an
    administrative user.

  - When Cortana retrieves data from user input services without consideration for
    status.

  - When the Windows kernel improperly initializes objects in memory.

  - In the way that the Windows Code Integrity Module performs hashing.

  - When Microsoft Edge improperly handles requests of different origins.

  - In the way that the Windows Kernel API enforces permissions.

  - When Microsoft Edge improperly handles objects in memory.

  - When Microsoft Edge improperly accesses objects in memory.

  - When Windows Media Foundation improperly handles objects in memory.

  - When HTTP Protocol Stack (Http.

  - When the Windows GDI component improperly discloses the contents of its
    memory.

  - When Windows Hyper-V instruction emulation fails to properly enforce privilege
    levels.

  - When Windows NT WEBDAV Minirdr attempts to query a WEBDAV directory.

  - When Microsoft Hyper-V Network Switch on a host server fails to properly
    validate input from a privileged user on a guest operating system.

  - In Internet Explorer that allows for bypassing Mark of the Web Tagging (MOTW).

  - When Internet Explorer improperly accesses objects in memory.

  - When NTFS improperly checks access.

  - When Edge improperly marks files.

  - In the way that the Chakra scripting engine handles objects in memory in
    Microsoft Edge.

  - In the way that the scripting engine handles objects in memory in Internet
    Explorer.

  - In Windows Domain Name System (DNS) DNSAPI.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system, run processes in
  an elevated context, inject code into a trusted PowerShell process, execute
  arbitrary code, read privileged data, force the browser to send restricted data,
  interject cross-process communication, install programs, view, change, or delete
  data or create new accounts with full user rights and create a denial of service
  condition.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1709 for x32/x64-bit Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4284819");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.16299.0", test_version2:"11.0.16299.491"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.16299.0 - 11.0.16299.491");
  security_message(data:report);
  exit(0);
}
exit(99);
