# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2845");
  script_cve_id("CVE-2022-25308", "CVE-2022-25309", "CVE-2022-25310");
  script_tag(name:"creation_date", value:"2022-12-22 04:14:54 +0000 (Thu, 22 Dec 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-08 14:49:00 +0000 (Thu, 08 Sep 2022)");

  script_name("Huawei EulerOS: Security Advisory for fribidi (EulerOS-SA-2022-2845)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2845");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2845");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'fribidi' package(s) announced via the EulerOS-SA-2022-2845 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow flaw was found in the Fribidi package. This flaw allows an attacker to pass a specially crafted file to the Fribidi application, which leads to a possible memory leak or a denial of service.(CVE-2022-25308)

A heap-based buffer overflow flaw was found in the Fribidi package and affects the fribidi_cap_rtl_to_unicode() function of the fribidi-char-sets-cap-rtl.c file. This flaw allows an attacker to pass a specially crafted file to the Fribidi application with the '--caprtl' option, leading to a crash and causing a denial of service.(CVE-2022-25309)

A segmentation fault (SEGV) flaw was found in the Fribidi package and affects the fribidi_remove_bidi_marks() function of the lib/fribidi.c file. This flaw allows an attacker to pass a specially crafted file to Fribidi, leading to a crash and causing a denial of service.(CVE-2022-25310)");

  script_tag(name:"affected", value:"'fribidi' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"fribidi", rpm:"fribidi~1.0.10~1.h2.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fribidi-devel", rpm:"fribidi-devel~1.0.10~1.h2.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
