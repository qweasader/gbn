# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1052");
  script_cve_id("CVE-2016-5008");
  script_tag(name:"creation_date", value:"2020-01-23 10:46:42 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-14 15:57:17 +0000 (Thu, 14 Jul 2016)");

  script_name("Huawei EulerOS: Security Advisory for libvirt (EulerOS-SA-2017-1052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1052");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1052");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libvirt' package(s) announced via the EulerOS-SA-2017-1052 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that setting a VNC password to an empty string in libvirt did not disable all access to the VNC server as documented, instead it allowed access with no authentication required. An attacker could use this flaw to access a VNC server with an empty VNC password without any authentication.(CVE-2016-5008)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvirt-daemon-kvm", rpm:"libvirt-daemon-kvm~2.0.0~10.5", rls:"EULEROS-2.0SP2"))) {
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
