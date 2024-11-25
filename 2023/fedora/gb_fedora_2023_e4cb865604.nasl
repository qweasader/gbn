# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885271");
  script_cve_id("CVE-2023-23583");
  script_tag(name:"creation_date", value:"2023-11-17 02:14:07 +0000 (Fri, 17 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-28 17:07:45 +0000 (Tue, 28 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-e4cb865604)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-e4cb865604");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-e4cb865604");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode_ctl' package(s) announced via the FEDORA-2023-e4cb865604 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to upstream 2.1-42. 20231114
 - Update of 06-6a-06/0x87 (ICX-SP D0) microcode from revision 0xd0003a5
 up to 0xd0003b9,
 - Update of 06-6c-01/0x10 (ICL-D B0) microcode from revision 0x1000230
 up to 0x1000268,
 - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0xbc
 up to 0xc2,
 - Update of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode from revision
 0xac up to 0xb4,
 - Update of 06-8c-02/0xc2 (TGL-R C0) microcode from revision 0x2c up
 to 0x34,
 - Update of 06-8d-01/0xc2 (TGL-H R0) microcode from revision 0x46 up
 to 0x4e,
 - Update of 06-8f-04/0x10 microcode from revision 0x2c000271 up to
 0x2c000290,
 - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode from revision
 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
 intel-ucode/06-8f-04) from revision 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-05/0x87 (SPR-SP E2) microcode (in
 intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-04) from
 revision 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
 intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
 intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
 intel-ucode/06-8f-04) from revision 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
 intel-ucode/06-8f-04) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-05) from
 revision 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
 intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode from revision
 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-05/0x87 (SPR-SP E2) microcode from revision 0x2b0004b1
 up to 0x2b0004d0,
 - Update of 06-8f-06/0x10 microcode (in intel-ucode/06-8f-05) from
 revision 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-06/0x87 (SPR-SP E3) microcode (in
 intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-07/0x87 (SPR-SP E4/S2) microcode (in
 intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-08/0x10 (SPR-HBM B3) microcode (in
 intel-ucode/06-8f-05) from revision 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-08/0x87 (SPR-SP E5/S3) microcode (in
 intel-ucode/06-8f-05) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-04/0x10 microcode (in intel-ucode/06-8f-06) from
 revision 0x2c000271 up to 0x2c000290,
 - Update of 06-8f-04/0x87 (SPR-SP E0/S1) microcode (in
 intel-ucode/06-8f-06) from revision 0x2b0004b1 up to 0x2b0004d0,
 - Update of 06-8f-05/0x10 (SPR-HBM B1) microcode (in
 intel-ucode/06-8f-06) from revision 0x2c000271 up to 0x2c000290,
 - Update of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'microcode_ctl' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"microcode_ctl", rpm:"microcode_ctl~2.1~58.fc39", rls:"FC39"))) {
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
