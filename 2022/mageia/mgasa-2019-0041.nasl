# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0041");
  script_cve_id("CVE-2018-20174", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-20177", "CVE-2018-20178", "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182", "CVE-2018-8791", "CVE-2018-8792", "CVE-2018-8793", "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8796", "CVE-2018-8797", "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-29 01:09:00 +0000 (Tue, 29 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0041");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0041.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24192");
  script_xref(name:"URL", value:"https://github.com/rdesktop/rdesktop/releases/tag/v1.8.4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rdesktop' package(s) announced via the MGASA-2019-0041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"rdesktop has been updated to fix multiple CVE's.
Fix memory corruption in process_bitmap_data - CVE-2018-8794
Fix remote code execution in process_bitmap_data - CVE-2018-8795
Fix remote code execution in process_plane - CVE-2018-8797
Fix Denial of Service in mcs_recv_connect_response - CVE-2018-20175
Fix Denial of Service in mcs_parse_domain_params - CVE-2018-20175
Fix Denial of Service in sec_parse_crypt_info - CVE-2018-20176
Fix Denial of Service in sec_recv - CVE-2018-20176
Fix minor information leak in rdpdr_process - CVE-2018-8791
Fix Denial of Service in cssp_read_tsrequest - CVE-2018-8792
Fix remote code execution in cssp_read_tsrequest - CVE-2018-8793
Fix Denial of Service in process_bitmap_data - CVE-2018-8796
Fix minor information leak in rdpsnd_process_ping - CVE-2018-8798
Fix Denial of Service in process_secondary_order - CVE-2018-8799
Fix remote code execution in ui_clip_handle_data - CVE-2018-8800
Fix major information leak in ui_clip_handle_data - CVE-2018-20174
Fix memory corruption in rdp_in_unistr - CVE-2018-20177
Fix Denial of Service in process_demand_active - CVE-2018-20178
Fix remote code execution in lspci_process - CVE-2018-20179
Fix remote code execution in rdpsnddbg_process - CVE-2018-20180
Fix remote code execution in seamless_process - CVE-2018-20181
Fix remote code execution in seamless_process_line - CVE-2018-20182");

  script_tag(name:"affected", value:"'rdesktop' package(s) on Mageia 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"rdesktop", rpm:"rdesktop~1.8.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
