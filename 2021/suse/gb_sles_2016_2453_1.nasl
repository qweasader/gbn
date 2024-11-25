# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2453.1");
  script_cve_id("CVE-2016-5350", "CVE-2016-5351", "CVE-2016-5352", "CVE-2016-5353", "CVE-2016-5354", "CVE-2016-5355", "CVE-2016-5356", "CVE-2016-5357", "CVE-2016-5358", "CVE-2016-5359", "CVE-2016-6504", "CVE-2016-6505", "CVE-2016-6506", "CVE-2016-6507", "CVE-2016-6508", "CVE-2016-6509", "CVE-2016-6510", "CVE-2016-6511");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-09 18:45:46 +0000 (Tue, 09 Aug 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2453-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2453-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162453-1/");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.12.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.12.13.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2016:2453-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"wireshark was updated to version 1.12.13 to fix the following issues:
- CVE-2016-6504: wireshark: NDS dissector crash (bnc#991012)
- CVE-2016-6505: wireshark: PacketBB dissector could divide by zero
 (bnc#991013)
- CVE-2016-6506: wireshark: WSP infinite loop (bnc#991015)
- CVE-2016-6507: wireshark: MMSE infinite loop (bnc#991016)
- CVE-2016-6508: wireshark: RLC long loop (bnc#991017)
- CVE-2016-6509: wireshark: LDSS dissector crash (bnc#991018)
- CVE-2016-6510: wireshark: RLC dissector crash (bnc#991019)
- CVE-2016-6511: wireshark: OpenFlow long loop (bnc991020)
- CVE-2016-5350: SPOOLS infinite loop (bsc#983671).
- CVE-2016-5351: IEEE 802.11 dissector crash (bsc#983671).
- CVE-2016-5352: IEEE 802.11 dissector crash, different from
 wpna-sec-2016-30 (bsc#983671).
- CVE-2016-5353: UMTS FP crash (bsc#983671).
- CVE-2016-5354: USB dissector crash (bsc#983671).
- CVE-2016-5355: Toshiba file parser crash (bsc#983671).
- CVE-2016-5356: CoSine file parser crash (bsc#983671).
- CVE-2016-5357: NetScreen file parser crash (bsc#983671).
- CVE-2016-5358: Ethernet dissector crash (bsc#983671).
- CVE-2016-5359: WBXML infinite loop (bsc#983671).
For more details please see:
[link moved to references] [link moved to references]");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.12.13~31.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~1.12.13~31.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~1.12.13~31.1", rls:"SLES12.0SP1"))) {
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
