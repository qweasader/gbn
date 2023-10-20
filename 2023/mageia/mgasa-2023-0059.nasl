# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0059");
  script_cve_id("CVE-2019-13590", "CVE-2021-23159", "CVE-2021-23172", "CVE-2021-23210", "CVE-2021-33844", "CVE-2021-3643", "CVE-2021-40426", "CVE-2022-3165", "CVE-2022-31650");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 17:00:00 +0000 (Tue, 10 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0059)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0059");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0059.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30291");
  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2021-1434");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3315");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sox' package(s) announced via the MGASA-2023-0059 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-13590: sox-fmt validation
CVE-2021-3643 and CVE-2021-23210: voc validation
CVE-2021-23159 and CVE-2021-23172: hcom validation
CVE-2021-33844: wav validation
CVE-2021-40426: sphere validation
CVE-2022-31650: aiff validation
CVE-2022-31651: reject implausible rate");

  script_tag(name:"affected", value:"'sox' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sox-devel", rpm:"lib64sox-devel~14.4.3~0.git20200117.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sox3", rpm:"lib64sox3~14.4.3~0.git20200117.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox-devel", rpm:"libsox-devel~14.4.3~0.git20200117.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsox3", rpm:"libsox3~14.4.3~0.git20200117.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sox", rpm:"sox~14.4.3~0.git20200117.3.1.mga8", rls:"MAGEIA8"))) {
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
