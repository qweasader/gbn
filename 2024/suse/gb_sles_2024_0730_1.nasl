# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0730.1");
  script_cve_id("CVE-2023-46809", "CVE-2024-21892", "CVE-2024-22019", "CVE-2024-22025", "CVE-2024-24758", "CVE-2024-24806");
  script_tag(name:"creation_date", value:"2024-03-01 04:23:12 +0000 (Fri, 01 Mar 2024)");
  script_version("2024-03-01T05:06:51+0000");
  script_tag(name:"last_modification", value:"2024-03-01 05:06:51 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-27 18:34:10 +0000 (Tue, 27 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0730-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240730-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs18' package(s) announced via the SUSE-SU-2024:0730-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs18 fixes the following issues:
Update to 18.19.1: (security updates)

CVE-2024-21892: Code injection and privilege escalation through Linux capabilities (bsc#1219992).
CVE-2024-22019: http: Reading unprocessed HTTP request with unbounded chunk extension allows DoS attacks (bsc#1219993).
CVE-2023-46809: Node.js is vulnerable to the Marvin Attack (timing variant of the Bleichenbacher attack against PKCS#1 v1.5 padding) (bsc#1219997).
CVE-2024-22025: Denial of Service by resource exhaustion in fetch() brotli decoding (bsc#1220014).
CVE-2024-24758: undici version 5.28.3 (bsc#1220017).
CVE-2024-24806: libuv version 1.48.0 (bsc#1219724).

Update to LTS version 18.19.0

deps: npm updates to 10.x esm:
Leverage loaders when resolving subsequent loaders import.meta.resolve unflagged
--experimental-default-type flag to flip module defaults");

  script_tag(name:"affected", value:"'nodejs18' package(s) on SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs18", rpm:"nodejs18~18.19.1~150400.9.18.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debuginfo", rpm:"nodejs18-debuginfo~18.19.1~150400.9.18.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-debugsource", rpm:"nodejs18-debugsource~18.19.1~150400.9.18.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-devel", rpm:"nodejs18-devel~18.19.1~150400.9.18.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs18-docs", rpm:"nodejs18-docs~18.19.1~150400.9.18.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm18", rpm:"npm18~18.19.1~150400.9.18.2", rls:"SLES15.0SP4"))) {
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
