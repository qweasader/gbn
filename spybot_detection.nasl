# SPDX-FileCopyrightText: 2008 Josh Zlatin-Amishav and Tenable Network Security
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80045");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Spybot Search & Destroy Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Josh Zlatin-Amishav and Tenable Network Security");
  script_family("Service detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.safer-networking.org/");

  script_tag(name:"summary", value:"The remote Windows host is running Spybot Search & Destroy, a privacy
  enhancing application that can detect and remove spyware of different
  kinds from your computer.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  tmp = registry_get_sz(item:"DisplayName", key:key + entry);

  if(tmp && "Spybot" >< tmp) {

    version = registry_get_sz(item:"DisplayVersion", key:key + entry);
    if(!isnull(version)) {
      set_kb_item(name:"SMB/SpybotSD/version", value:version);
    }

    path = registry_get_sz(item:"InstallLocation", key:key + entry);

    if(path) {
      path += "Updates\downloaded.ini";
      contents = smb_read_file(fullpath:path, offset:0, count:85);

      if(contents && "ReleaseDate" >< contents) {

        sigs_target = strstr(contents, "ReleaseDate=");
        if (strlen(sigs_target) >= 22) sigs_target = substr(sigs_target, 12, 22);
        if (isnull(sigs_target)) sigs_target = "n/a";

        if (sigs_target =~ "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]") {
          a = split(sigs_target, sep:"-", keep:0);
          sigs_target_yyyymmdd = string(a[0], a[1], a[2]);
          sigs_target_mmddyyyy = string(a[1], "/", a[2], "/", a[0]);
        } else {
          sigs_target_mmddyyyy = "n/a";
        }

        if(version && sigs_target_mmddyyyy) {
          report = string("Version    : ", version, "\n",
                          "Signatures : ", sigs_target_mmddyyyy);
          log_message(port:0, data:report);
          exit(0);
        }
      }
    }
    break;
  }
}

exit(0);