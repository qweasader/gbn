# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1484");
  script_cve_id("CVE-2017-12169");
  script_tag(name:"creation_date", value:"2021-03-05 07:08:23 +0000 (Fri, 05 Mar 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-17 01:29:00 +0000 (Tue, 17 Apr 2018)");

  script_name("Huawei EulerOS: Security Advisory for ipa (EulerOS-SA-2021-1484)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1484");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1484");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ipa' package(s) announced via the EulerOS-SA-2021-1484 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that FreeIPA 4.2.0 and later could disclose password hashes to users having the 'System: Read Stage Users' permission. A remote, authenticated attacker could potentially use this flaw to disclose the password hashes belonging to Stage Users. This security issue does not result in disclosure of password hashes belonging to active standard users. NOTE: some developers feel that this report is a suggestion for a design change to Stage User activation, not a statement of a vulnerability.(CVE-2017-12169)");

  script_tag(name:"affected", value:"'ipa' package(s) on Huawei EulerOS Virtualization 3.0.6.6.");

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

if(release == "EULEROSVIRT-3.0.6.6") {

  if(!isnull(res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-client-common", rpm:"ipa-client-common~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-common", rpm:"ipa-common~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-python-compat", rpm:"ipa-python-compat~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-common", rpm:"ipa-server-common~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-dns", rpm:"ipa-server-dns~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-ipaclient", rpm:"python2-ipaclient~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-ipalib", rpm:"python2-ipalib~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-ipaserver", rpm:"python2-ipaserver~4.5.4~10.3.h5.eulerosv2r7", rls:"EULEROSVIRT-3.0.6.6"))) {
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
