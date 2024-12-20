# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0422");
  script_cve_id("CVE-2020-8694", "CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-24 15:31:57 +0000 (Tue, 24 Nov 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0422)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0422");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0422.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:5085");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26995");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27597");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00381.html");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00389.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2020-0422 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient access control in the Linux kernel driver for some Intel(R)
Processors may allow an authenticated user to potentially enable information
disclosure via local access. (CVE-2020-8694)

Observable discrepancy in the RAPL interface for some Intel(R) Processors may
allow a privileged user to potentially enable information disclosure via local
access. (CVE-2020-8695)

Improper removal of sensitive information before storage or transfer in some
Intel(R) Processors may allow an authenticated user to potentially enable
information disclosure via local access. (CVE-2020-8696)

Improper isolation of shared resources in some Intel(R) Processors may allow
an authenticated user to potentially enable information disclosure via local
access. (CVE-2020-8698)");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20201110~1.mga7.nonfree", rls:"MAGEIA7"))) {
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
