# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1036");
  script_cve_id("CVE-2019-11555", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"creation_date", value:"2020-01-23 13:17:01 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-22 17:15:00 +0000 (Thu, 22 Oct 2020)");

  script_name("Huawei EulerOS: Security Advisory for wpa_supplicant (EulerOS-SA-2020-1036)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1036");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1036");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'wpa_supplicant' package(s) announced via the EulerOS-SA-2020-1036 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The implementations of EAP-PWD in hostapd EAP Server and wpa_supplicant EAP Peer do not validate the scalar and element values in EAP-pwd-Commit. This vulnerability may allow an attacker to complete EAP-PWD authentication without knowing the password. However, unless the crypto library does not implement additional checks for the EC point, the attacker will not be able to derive the session key or complete the key exchange. Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including version 2.4 are affected. Both hostapd with EAP-pwd support and wpa_supplicant with EAP-pwd support prior to and including version 2.7 are affected.(CVE-2019-9497)

The implementations of EAP-PWD in hostapd EAP Server, when built against a crypto library missing explicit validation on imported elements, do not validate the scalar and element values in EAP-pwd-Commit. An attacker may be able to use invalid scalar/element values to complete authentication, gaining session key and network access without needing or learning the password. Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including version 2.4 are affected. Both hostapd with EAP-pwd support and wpa_supplicant with EAP-pwd support prior to and including version 2.7 are affected.(CVE-2019-9498)

The implementations of EAP-PWD in wpa_supplicant EAP Peer, when built against a crypto library missing explicit validation on imported elements, do not validate the scalar and element values in EAP-pwd-Commit. An attacker may complete authentication, session key and control of the data connection with a client. Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including version 2.4 are affected. Both hostapd with EAP-pwd support and wpa_supplicant with EAP-pwd support prior to and including version 2.7 are affected.(CVE-2019-9499)

The EAP-pwd implementation in hostapd (EAP server) before 2.8 and wpa_supplicant (EAP peer) before 2.8 does not validate fragmentation reassembly state properly for a case where an unexpected fragment could be received. This could result in process termination due to a NULL pointer dereference (denial of service). This affects eap_server/eap_server_pwd.c and eap_peer/eap_pwd.c.(CVE-2019-11555)");

  script_tag(name:"affected", value:"'wpa_supplicant' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"wpa_supplicant", rpm:"wpa_supplicant~2.6~17.h4.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
