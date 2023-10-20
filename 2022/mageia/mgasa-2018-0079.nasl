# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0079");
  script_cve_id("CVE-2017-5715");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0079)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0079");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0079.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22337");
  script_xref(name:"URL", value:"https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00088&languageid=en-fr");
  script_xref(name:"URL", value:"https://downloadcenter.intel.com/download/27431/Linux-Processor-Microcode-Data-File?product=52214");
  script_xref(name:"URL", value:"http://www.amd.com/en/corporate/speculative-execution");
  script_xref(name:"URL", value:"https://meltdownattack.com/");
  script_xref(name:"URL", value:"https://security.googleblog.com/2018/01/todays-cpu-vulnerability-what-you-need.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2018-0079 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides microcode fixes and mitigations for Spectre
(CVE-2017-5715) for many Intel CPUs produced in the last 5 years.

So far the Intel microcode updates are for several processors from the
Haswell, Broadwell, Skylake, Kaby Lake, Coffee Lake, Gemini Lake,
Apollo Lake, Crystal Well and IVT platforms

We also have added the latest known microcode for Amd family 17 (Zen)
processors.

We will provide more microcode updates when they are made available
by Intel and Amd.

We also suggest that you check if there is updated BIOS and EFI
firmwares from your hardware vendor.");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20180108~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20180108~1.mga6.nonfree", rls:"MAGEIA6"))) {
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
