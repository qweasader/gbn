# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0437");
  script_cve_id("CVE-2022-39282", "CVE-2022-39283");
  script_tag(name:"creation_date", value:"2022-11-25 04:11:46 +0000 (Fri, 25 Nov 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-13 17:36:19 +0000 (Thu, 13 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0437)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0437");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0437.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31136");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/releases/tag/2.8.1");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-6cf9-3328-qrvh");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-c45q-wcpg-mxjq");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HJA3DXXYKZSQPM7VF5GX343WBGCGAPAH/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/012920.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2022-0437 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeRDP based clients on unix systems using `/parallel` command line
switch might read uninitialized data and send it to the server the client
is currently connected to. (CVE-2022-39282)

All FreeRDP based clients when using the `/video` command line switch
might read uninitialized data, decode it as audio/video and display the
result. (CVE-2022-39283)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.2.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.2.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.2.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.2.0~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.2.0~1.3.mga8", rls:"MAGEIA8"))) {
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
