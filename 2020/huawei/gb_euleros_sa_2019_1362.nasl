# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1362");
  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2020-01-23 11:40:27 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 17:45:21 +0000 (Tue, 26 Mar 2019)");

  script_name("Huawei EulerOS: Security Advisory for libssh2 (EulerOS-SA-2019-1362)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.5\.3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1362");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1362");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libssh2' package(s) announced via the EulerOS-SA-2019-1362 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw which could lead to an out of bounds write was discovered in libssh2 in the way packets are read from the server. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.(CVE-2019-3855)

An integer overflow flaw, which could lead to an out of bounds write, was discovered in libssh2 in the way keyboard prompt requests are parsed. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.(CVE-2019-3856)

An integer overflow flaw which could lead to an out of bounds write was discovered in libssh2 in the way SSH_MSG_CHANNEL_REQUEST packets with an exit signal are parsed. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.(CVE-2019-3857)

A flaw was found in libssh2 before 1.8.1. A server could send multiple keyboard interactive response messages whose total length are greater than unsigned char max characters. This value is used as an index to copy memory causing in an out of bounds memory write error.(CVE-2019-3863)");

  script_tag(name:"affected", value:"'libssh2' package(s) on Huawei EulerOS Virtualization 2.5.3.");

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

if(release == "EULEROSVIRT-2.5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.4.3~10.1.h1", rls:"EULEROSVIRT-2.5.3"))) {
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
