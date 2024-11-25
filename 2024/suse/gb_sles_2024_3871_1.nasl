# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3871.1");
  script_cve_id("CVE-2023-50782", "CVE-2024-41996");
  script_tag(name:"creation_date", value:"2024-11-04 04:26:45 +0000 (Mon, 04 Nov 2024)");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-14 17:52:10 +0000 (Wed, 14 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3871-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3871-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243871-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-3' package(s) announced via the SUSE-SU-2024:3871-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-3 fixes the following issues:

CVE-2023-50782: Implicit rejection in PKCS#1 v1.5 (bsc#1220262)
CVE-2024-41996: Avoid expensive public key validation for known safe-prime groups (DHEATATTACK) (bsc#1230698)");

  script_tag(name:"affected", value:"'openssl-3' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP4, SUSE Manager Server 4.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel", rpm:"libopenssl-3-devel~3.0.8~150400.4.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.8~150400.4.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-debuginfo", rpm:"libopenssl3-debuginfo~3.0.8~150400.4.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3", rpm:"openssl-3~3.0.8~150400.4.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debuginfo", rpm:"openssl-3-debuginfo~3.0.8~150400.4.69.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debugsource", rpm:"openssl-3-debugsource~3.0.8~150400.4.69.1", rls:"SLES15.0SP4"))) {
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
