# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1310");
  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");
  script_tag(name:"creation_date", value:"2020-01-23 11:38:57 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:42:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Huawei EulerOS: Security Advisory for libssh2 (EulerOS-SA-2019-1310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1310");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1310");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libssh2' package(s) announced via the EulerOS-SA-2019-1310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out of bounds read flaw was discovered in libssh2 when a specially crafted SFTP packet is received from the server. A remote attacker who compromises a SSH server may be able to cause a denial of service or read data in the client memory.(CVE-2019-3858)

An out of bounds read flaw was discovered in libssh2 in the _libssh2_packet_require and _libssh2_packet_requirev functions. A remote attacker who compromises a SSH server may be able to cause a denial of service or read data in the client memory.(CVE-2019-3859)

An out of bounds read flaw was discovered in libssh2 in the way SFTP packets with empty payloads are parsed. A remote attacker who compromises a SSH server may be able to cause a denial of service or read data in the client memory.(CVE-2019-3860)

An out of bounds read flaw was discovered in libssh2 in the way SSH packets with a padding length value greater than the packet length are parsed. A remote attacker who compromises a SSH server may be able to cause a denial of service or read data in the client memory.(CVE-2019-3861)

An out of bounds read flaw was discovered in libssh2 in the way SSH_MSG_CHANNEL_REQUEST packets with an exit status message and no payload are parsed. A remote attacker who compromises a SSH server may be able to cause a denial of service or read data in the client memory.(CVE-2019-3862)

An integer overflow flaw which could lead to an out of bounds write was discovered in libssh2 in the way packets are read from the server. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.(CVE-2019-3855)

An integer overflow flaw, which could lead to an out of bounds write, was discovered in libssh2 in the way keyboard prompt requests are parsed. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.(CVE-2019-3856)

An integer overflow flaw which could lead to an out of bounds write was discovered in libssh2 in the way SSH_MSG_CHANNEL_REQUEST packets with an exit signal are parsed. A remote attacker who compromises a SSH server may be able to execute code on the client system when a user connects to the server.(CVE-2019-3857)

A flaw was found in libssh2 before 1.8.1. A server could send multiple keyboard interactive response messages whose total length are greater than unsigned char max characters. This value is used as an index to copy memory causing in an out of bounds memory write error.(CVE-2019-3863)");

  script_tag(name:"affected", value:"'libssh2' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.4.3~10.1.h3.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
