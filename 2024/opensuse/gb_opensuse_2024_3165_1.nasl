# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856456");
  script_version("2024-09-25T05:06:11+0000");
  script_cve_id("CVE-2023-0414", "CVE-2023-0666", "CVE-2023-2854", "CVE-2023-3649", "CVE-2023-5371", "CVE-2023-6174", "CVE-2023-6175", "CVE-2024-0207", "CVE-2024-0210", "CVE-2024-0211", "CVE-2024-2955");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-10 14:11:32 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-09-11 04:00:28 +0000 (Wed, 11 Sep 2024)");
  script_name("openSUSE: Security Advisory for wireshark (SUSE-SU-2024:3165-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3165-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VF7WSGKJC5WOOEYSYIOQ63OENTPWAKKQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the SUSE-SU-2024:3165-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark fixes the following issues:

  wireshark was updated from version 3.6.23 to version 4.2.6 (jsc#PED-8517):

  * Security issues fixed with this update:

  * CVE-2024-0207: HTTP3 dissector crash (bsc#1218503)

  * CVE-2024-0210: Zigbee TLV dissector crash (bsc#1218506)

  * CVE-2024-0211: DOCSIS dissector crash (bsc#1218507)

  * CVE-2023-6174: Fixed SSH dissector crash (bsc#1217247)

  * CVE-2023-6175: NetScreen file parser crash (bsc#1217272)

  * CVE-2023-5371: RTPS dissector memory leak (bsc#1215959)

  * CVE-2023-3649: iSCSI dissector crash (bsc#1213318)

  * CVE-2023-2854: BLF file parser crash (bsc#1211708)

  * CVE-2023-0666: RTPS dissector crash (bsc#1211709)

  * CVE-2023-0414: EAP dissector crash (bsc#1207666)

  * Major changes introduced with versions 4.2.0 and 4.0.0:

  * Added an additional desktop file to start wireshark which asks for the super
      user password.

  ##");

  script_tag(name:"affected", value:"'wireshark' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap14", rpm:"libwiretap14~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark17", rpm:"libwireshark17~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil15-debuginfo", rpm:"libwsutil15-debuginfo~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil15", rpm:"libwsutil15~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark17-debuginfo", rpm:"libwireshark17-debuginfo~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap14-debuginfo", rpm:"libwiretap14-debuginfo~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~4.2.6~150600.18.6.1", rls:"openSUSELeap15.6"))) {
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
