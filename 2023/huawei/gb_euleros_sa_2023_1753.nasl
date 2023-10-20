# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1753");
  script_cve_id("CVE-2021-33643", "CVE-2021-33644", "CVE-2021-33645", "CVE-2021-33646");
  script_tag(name:"creation_date", value:"2023-05-08 04:14:25 +0000 (Mon, 08 May 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-13 00:17:00 +0000 (Sat, 13 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for libtar (EulerOS-SA-2023-1753)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1753");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1753");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libtar' package(s) announced via the EulerOS-SA-2023-1753 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The th_read() function doesn't free a variable t->th_buf.gnu_longname after allocating memory, which may cause a memory leak.(CVE-2021-33646)

The th_read() function doesn't free a variable t->th_buf.gnu_longlink after allocating memory, which may cause a memory leak.(CVE-2021-33645)

An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longname, causing an out-of-bounds read.(CVE-2021-33644)

An attacker who submits a crafted tar file with size in header struct being 0 may be able to trigger an calling of malloc(0) for a variable gnu_longlink, causing an out-of-bounds read.(CVE-2021-33643)");

  script_tag(name:"affected", value:"'libtar' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"libtar", rpm:"libtar~1.2.11~29.h3", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
