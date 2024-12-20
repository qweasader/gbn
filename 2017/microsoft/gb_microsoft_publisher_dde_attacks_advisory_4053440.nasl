# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812078");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-11-10 15:53:35 +0530 (Fri, 10 Nov 2017)");
  script_name("Microsoft Publisher 'Dynamic Data Exchange (DDE)' Attacks Security Advisory (4053440)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Advisory 4053440.");

  script_tag(name:"vuldetect", value:"Get the installed application version and
  check through the registry whether appropriate DDE features are disabled or not.");

  script_tag(name:"insight", value:"The flaw exists as the Microsoft Office provides
  several methods for transferring data between applications and the 'DDE' protocol
  is one such set of messages and guidelines. It sends messages between applications
  that share data, and uses shared memory to exchange data between applications.
  Applications can use the DDE protocol for one-time data transfers and for
  continuous exchanges in which applications send updates to one another as new
  data becomes available.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to perform code execution on the targeted device.");

  script_tag(name:"affected", value:"- Microsoft Publisher 2016

  - Microsoft Publisher 2013

  - Microsoft Publisher 2010

  - Microsoft Publisher 2007");

  script_tag(name:"solution", value:"Disable the DDE feature via the registry
  editor or user interface as given in advisory.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/4053440");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Publisher/Version");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

pubVer = get_kb_item("SMB/Office/Publisher/Version");
if(!pubVer)
  exit(0);

if(pubVer =~ "^16\.")
  offVer = "16.0";
else if(pubVer =~ "^15\.")
  offVer = "15.0";
else if(pubVer =~ "^14\.")
  offVer = "14.0";
else if(pubVer =~ "^12\.")
  offVer = "12.0";
else
  exit(99);

if(offVer =~ "^1[4-6]") {
  keyOff = "Software\Microsoft\Office\" + offVer + "\Word\Options";
  item = "DontUpdateLinks";
} else if(offVer =~ "^12") {
  keyOff = "Software\Microsoft\Office\" + offVer + "\Word\Options\vpref";
  item = "fNoCalclinksOnopen_90_1";
}

if(!registry_key_exists(key:keyOff, type:"HKCU"))
  exit(0);

ddedisableitem = registry_get_dword(key:keyOff, item:item, type:"HKCU");

# TODO: We need something like registry_item_exists() similar to registry_key_exists() as registry_get_dword will
# return NULL for a non-existent item as well as if there was e.g. a connectivity problem to the remote host.
if(isnull(ddedisableitem))
  exit(0);

# nb: DDE disabled == 1. If item not present or ddedisableitem == 0, then DDE enabled
if(ddedisableitem == "1") {
  exit(99);
} else {

  pubPath = get_kb_item("SMB/Office/Publisher/Installed/Path");
  if(!pubPath)
    pubPath = "Unable to fetch the install path from the registry";

  report  = "Reg-Key checked:  HKCU\" + keyOff + '\n';
  report += 'Reg-Item checked: ' + item + '\n';
  report += 'Expected value:   1\n';
  report += 'Current value:    ' + ddedisableitem + '\n\n';
  report += 'Install path:     ' + pubPath;
  security_message(port:0, data:report);
  exit(0);
}

exit(99);